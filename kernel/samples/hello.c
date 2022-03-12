#include <linux/module.h>
static int __init hello_init(void)
{
        printk(KERN_INFO "Hello world!\n");
        return 0;
}
static void __exit hello_exit(void)
{
        printk(KERN_INFO "See you again.\n");
}
module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joseph Qi");
MODULE_DESCRIPTION("This is my first kernel module");

