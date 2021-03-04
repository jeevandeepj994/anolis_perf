// SPDX-License-Identifier: GPL-2.0
//
// FUSE IO metrics: IOPS, BPS and latency counters.

#include "fuse_i.h"
#include <linux/percpu.h>

/* default target 1 ms IO latency */
const u64 default_latency_target_ns = NSEC_PER_MSEC;
/* default to calculate metrics every second */
const u64 default_timer_period_us = USEC_PER_SEC;

enum {
	FIC_LATENCY_MET,
	FIC_LATENCY_MISSED,
	FIC_LATENCY_MISSED_X10,
	FIC_LATENCY_MISSED_X100,

	FIC_LATENCY_CNT,
};

struct fuse_io_stat {
	u64	nr_ops;
	u64	bytes;
	/* target_matched, target_missed, target_missed_x10 and target_missed_x100 */
	u64	latency_dist[FIC_LATENCY_CNT];
};

/* Per-cpu io stats */
struct fuse_io_stat_table {
	/* for READ(0) and WRITE(1) */
	struct fuse_io_stat	stat[2];
	struct fuse_io_stat	last_stat[2];
};

enum {
	FIC_IDLE,
	FIC_RUNNING,
	FIC_DANGLING,
	FIC_STOP,
};

struct fuse_io_metrics {
	u64	bps;
	u64	iops;
	u64	latency_dist[FIC_LATENCY_CNT];
};

struct fuse_io_counter {
	/* Protects timer addition */
	spinlock_t		lock;
	int			running;
	atomic_t		active_io;
	unsigned long long	latency_target_ns;
	unsigned long long	latency_target_ns_x10;
	unsigned long long	latency_target_ns_x100;
	unsigned long long	timer_period_us;
	unsigned long long	period_per_second;
	struct timer_list	timer;

	/* For READ(0) and WRITE(1) */
	struct fuse_io_metrics	metrics[2];
	spinlock_t		metrics_lock;

	struct fuse_io_stat_table __percpu	*pcpu_stat;
};

static void cal_delta_and_set(struct fuse_io_stat *stat,
			      struct fuse_io_stat *new,
			      struct fuse_io_stat *old)
{
	int i;

	stat->nr_ops += (new->nr_ops - old->nr_ops);
	stat->bytes += (new->bytes - old->bytes);
	for (i = FIC_LATENCY_MET; i < FIC_LATENCY_CNT; i++)
		stat->latency_dist[i] += (new->latency_dist[i] - old->latency_dist[i]);

	memcpy(old, new, sizeof(*new));
}

static void update_metrics(struct fuse_io_counter *fic, struct fuse_io_stat stat[2])
{
	bool overflow = false;
	int rw, i;

	spin_lock(&fic->metrics_lock);
retry:
	if (unlikely(overflow))
		memset(fic->metrics, 0, sizeof(fic->metrics));

	for (rw = READ; rw <= WRITE; rw++) {
		fic->metrics[rw].bps = stat[rw].bytes * fic->period_per_second;
		fic->metrics[rw].iops = stat[rw].nr_ops * fic->period_per_second;
		for (i = FIC_LATENCY_MET; i < FIC_LATENCY_CNT; i++) {
			u64 total = fic->metrics[rw].latency_dist[i] + stat[rw].latency_dist[i];

			if (unlikely(total < fic->metrics[rw].latency_dist[i])) {
				overflow = true;
				goto retry;
			}
			fic->metrics[rw].latency_dist[i] = total;
		}
	}

	spin_unlock(&fic->metrics_lock);
}

static void fuse_io_counter_start(struct fuse_io_counter *fic)
{
	fic->timer.expires = jiffies + usecs_to_jiffies(fic->timer_period_us);
	add_timer(&fic->timer);
}

static void fic_timer_fn(struct timer_list *t)
{
	struct fuse_io_counter *fic = from_timer(fic, t, timer);
	struct fuse_io_stat stat[2];
	int cpu, rw;

	memset(stat, 0, sizeof(stat));
	for_each_online_cpu(cpu) {
		struct fuse_io_stat_table *stats = per_cpu_ptr(fic->pcpu_stat, cpu);
		struct fuse_io_stat this_stat;

		for (rw = READ; rw <= WRITE; rw++) {
			this_stat = stats->stat[rw];
			cal_delta_and_set(&stat[rw], &this_stat, &stats->last_stat[rw]);
		}
	}

	update_metrics(fic, stat);

	switch (fic->running) {
	case FIC_RUNNING:
		/* dangling state ensures that we clear bps/iops */
		if (!atomic_read(&fic->active_io))
			fic->running = FIC_DANGLING;
		fuse_io_counter_start(fic);
		break;
	case FIC_DANGLING:
		if (atomic_read(&fic->active_io) > 0) {
			fic->running = FIC_RUNNING;
			fuse_io_counter_start(fic);
		} else {
			fic->running = FIC_IDLE;
		}
		break;
	default:
		fic->running = FIC_IDLE;
		break;
	}
}

void fuse_io_counter_set_latency_target(struct fuse_io_counter *fic,
					u64 target_ns)
{
	if (fic) {
		spin_lock(&fic->metrics_lock);
		fic->latency_target_ns = target_ns;
		fic->latency_target_ns_x10 = target_ns * 10;
		fic->latency_target_ns_x100 = target_ns * 100;
		memset(fic->metrics, 0, sizeof(fic->metrics));
		spin_unlock(&fic->metrics_lock);
	}
}

/* Init a fuse io counter */
int fuse_io_counter_init(struct fuse_conn *fc)
{
	struct fuse_io_counter *fic;

	fic = kzalloc(sizeof(*fic), GFP_KERNEL);
	if (!fic)
		return -ENOMEM;

	fic->pcpu_stat = alloc_percpu(struct fuse_io_stat_table);
	if (!fic->pcpu_stat) {
		kfree(fic);
		return -ENOMEM;
	}

	spin_lock_init(&fic->lock);
	spin_lock_init(&fic->metrics_lock);
	fic->running = FIC_IDLE;
	fuse_io_counter_set_latency_target(fic, default_latency_target_ns);
	fic->timer_period_us = default_timer_period_us;
	fic->period_per_second = USEC_PER_SEC / default_timer_period_us;
	timer_setup(&fic->timer, fic_timer_fn, 0);

	fc->io_counter = fic;

	return 0;
}

void fuse_io_counter_stop(struct fuse_conn *fc)
{
	struct fuse_io_counter *fic = fc->io_counter;

	if (fic) {
		fc->io_counter = NULL;
		fic->running = FIC_STOP;
		del_timer_sync(&fic->timer);
		free_percpu(fic->pcpu_stat);
		kfree(fic);
	}
}

int fuse_io_metrics_show(struct seq_file *s, void *unused)
{
	struct fuse_conn *fc = s->private;
	struct fuse_io_counter *fic;

	if (!fc)
		return -EINVAL;
	fic = fc->io_counter;
	if (!fic)
		return 0;

	seq_printf(s, "latency target(ns) %llu\n", fic->latency_target_ns);
	seq_printf(s, "read_bps %llu\n", fic->metrics[READ].bps);
	seq_printf(s, "read_iops %llu\n", fic->metrics[READ].iops);
	seq_printf(s, "read_lat_met %llu\n", fic->metrics[READ].latency_dist[FIC_LATENCY_MET]);
	seq_printf(s, "read_lat_missed %llu\n",
			fic->metrics[READ].latency_dist[FIC_LATENCY_MISSED]);
	seq_printf(s, "read_lat_missed_x10 %llu\n",
			fic->metrics[READ].latency_dist[FIC_LATENCY_MISSED_X10]);
	seq_printf(s, "read_lat_missed_x100 %llu\n",
			fic->metrics[READ].latency_dist[FIC_LATENCY_MISSED_X100]);

	seq_printf(s, "write_bps %llu\n", fic->metrics[WRITE].bps);
	seq_printf(s, "write_iops %llu\n", fic->metrics[WRITE].iops);
	seq_printf(s, "write_lat_met %llu\n",
			fic->metrics[WRITE].latency_dist[FIC_LATENCY_MET]);
	seq_printf(s, "write_lat_missed %llu\n",
			fic->metrics[WRITE].latency_dist[FIC_LATENCY_MISSED]);
	seq_printf(s, "write_lat_missed_x10 %llu\n",
			fic->metrics[WRITE].latency_dist[FIC_LATENCY_MISSED_X10]);
	seq_printf(s, "write_lat_missed_x100 %llu\n",
			fic->metrics[WRITE].latency_dist[FIC_LATENCY_MISSED_X100]);

	return 0;
}

static void fuse_io_counter_activate(struct fuse_io_counter *fic)
{
	/* We don't mind missing some io occasionally, so we don't force any
	 * memory consistency on fic->running w.r.t. fic_timer_fn(),
	 * but make sure we don't race add_timer() with fic->lock.
	 */
	if (fic->running == FIC_IDLE && spin_trylock(&fic->lock)) {
		if (fic->running == FIC_IDLE) {
			fic->running = FIC_RUNNING;
			fuse_io_counter_start(fic);
		}
		spin_unlock(&fic->lock);
	}
}

void fuse_io_start(struct fuse_io_counter *fic, struct fuse_req_stat *req,
		   size_t count, int type)
{
	if (WARN_ON_ONCE(type != READ && type != WRITE))
		return;

	req->type = type;
	req->count = count;
	req->start_time_ns = ktime_get_ns();

	atomic_inc(&fic->active_io);

	fuse_io_counter_activate(fic);
}

void fuse_io_end(struct fuse_io_counter *fic, struct fuse_req_stat *req)
{
	unsigned long long wait_ns = ktime_get_ns() - req->start_time_ns;
	struct fuse_io_stat *stat;
	int bucket;

	atomic_dec(&fic->active_io);

	if (likely(wait_ns <= fic->latency_target_ns))
		bucket = FIC_LATENCY_MET;
	else if (wait_ns <= fic->latency_target_ns_x10)
		bucket = FIC_LATENCY_MISSED;
	else if (wait_ns <= fic->latency_target_ns_x100)
		bucket = FIC_LATENCY_MISSED_X10;
	else
		bucket = FIC_LATENCY_MISSED_X100;

	stat = &get_cpu_ptr(fic->pcpu_stat)->stat[req->type];
	stat->nr_ops++;
	stat->bytes += req->count;
	stat->latency_dist[bucket]++;
	put_cpu_ptr(fic->pcpu_stat);
}
