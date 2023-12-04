#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
#
# The core script for ANCK kconfig baseline
# It is not recommended to call directly.
#
# Copyright (C) 2023 Qiao Ma <mqaio@linux.alibaba.com>

import argparse, re, os, glob, shutil, copy
from typing import List, Dict, Type
import json

def die(*args, **kwargs):
    print(*args, **kwargs)
    exit(1)

class ConfigRule():
    var_levels: List[str]
    var_levels = None

    @staticmethod
    def __get_env(env_name: str):
        value = os.getenv(env_name)
        if value == None:
            die(f"cannot find variable {env_name}")
        return value

    @staticmethod
    def levels() -> List[str]:
        if ConfigRule.var_levels == None:
            ConfigRule.var_levels = ConfigRule.__get_env("DIST_LEVELS").split()
        return ConfigRule.var_levels

    @staticmethod
    def lookup_order(arch: str) -> List[str]:
        return {
            "x86": ["x86", "default"],
            "x86-debug": ["x86-debug", "x86", "default"],
            "arm64": ["arm64", "default"],
            "arm64-debug": ["arm64-debug", "arm64", "default"],
        }[arch]

    @staticmethod
    def kernel_version() -> str:
        return ConfigRule.__get_env("DIST_KERNELVERSION")

    @staticmethod
    def dist_dependencies(dist: str) -> List[str]:
        return ConfigRule.__get_env(f"DIST_CONFIG_KERNEL_DEPENDENCIES_{dist}").split()

    @staticmethod
    def arch_list(dist: str) -> List[str]:
        return ConfigRule.__get_env(f"DIST_CONFIG_KERNEL_ARCHS_{dist}").split()

    @staticmethod
    def default_dist() -> str:
        return ConfigRule.__get_env("DIST_CONFIG_KERNEL_NAME")

    @staticmethod
    def is_override(dist: str) -> bool:
        return dist != "ANCK"

class ConfigValue():
    """ store config values"""
    def __init__(self, name: str, value: str) -> None:
        self.name = name
        self.value = value

    @staticmethod
    def from_text(line: str) -> Type["ConfigValue"] :
        RE_CONFIG_SET = r'^(CONFIG_\w+)=(.*)$'
        RE_CONFIG_NOT_SET = r'^# (CONFIG_\w+) is not set$'

        if re.match(RE_CONFIG_SET, line):
            obj = re.match(RE_CONFIG_SET, line)
            return ConfigValue(obj.group(1), obj.group(2))
        elif re.match(RE_CONFIG_NOT_SET, line):
            obj = re.match(RE_CONFIG_NOT_SET, line)
            return ConfigValue(obj.group(1), "n")
        return None

    def as_string(self) -> str:
        if self.value == None or self.value == "n":
            return f"# {self.name} is not set\n"
        return f"{self.name}={self.value}\n"

    def equal(self, another) -> bool:
        return self.value == another.value

    def is_empty(self) -> bool:
        return self.value == None

class ConfigValues():
    values: List[ConfigValue]

    def __init__(self) -> None:
        self.values = []

    def add_value(self, value: ConfigValue):
        self.values.append(value)

    @staticmethod
    def from_config_file(path: str) -> Type["ConfigValues"]:
        configs = ConfigValues()
        with open(path) as f:
            for line in f.readlines():
                value = ConfigValue.from_text(line)
                if value is None:
                    continue
                configs.add_value(value)
        return configs

class Config():
    name: str
    level: str
    values: Dict[str, ConfigValue]

    def __init__(self, name: str, level: str) -> None:
        self.name = name
        self.level = level
        self.values = {}

    def add_value(self, arch: str, value: str):
        self.values[arch] = value

    def get_value(self, arch: str):
        for arch in ConfigRule.lookup_order(arch):
            if arch in self.values:
                return self.values[arch]
        return None

    def __collapse_value(self, full_arch_list: List[str], collapse_archs: List[str], arch_new: str = None):
        base_value = None

        # for downstream distributions, the arch like arm64 may not be supported, ignore it
        final_archs = []
        for arch in collapse_archs:
            if arch in full_arch_list:
                final_archs.append(arch)

        if len(final_archs) == 0:
            return

        for arch in final_archs:
            if arch not in self.values:
                return
            if base_value == None:
                base_value = self.values[arch]
            elif not base_value.equal(self.values[arch]):
                return

        if arch_new == None:
            arch_new = final_archs[0]

        for arch in final_archs:
            del self.values[arch]

        self.values[arch_new] = base_value

    def __remove_empty_values(self, arch_list: List[str]):
        for arch in arch_list:
            if arch in self.values and f"{arch}-debug" not in self.values:
                if self.values[arch].is_empty():
                    del self.values[arch]

    def collapse_values(self, all_archs: List[str]):
        self.__collapse_value(all_archs, ["x86", "x86-debug"])
        self.__collapse_value(all_archs, ["arm64", "arm64-debug"])
        self.__collapse_value(all_archs, ["x86", "arm64"], "default")
        if "default" not in self.values:
            # Optimization for such case:
            # CONFIG_ARM_GIC_V3 only appears in arch arm64,
            # it is unnecessary to place related file in x86 arch,
            # so just remove it
            self.__remove_empty_values(["x86", "arm64"])
        elif self.values["default"].is_empty():
            # Optimization for such case:
            # CONFIG_FAILSLAB does not appear in x86, arm64,
            # it only appears in x86-debug, arm64-debug configs,
            # which finally causes a default file exists, but has its value like:
            # > # CONFIG_FAILSLAB is not appear
            # which looks ugly.
            del self.values["default"]

    def expand_values(self, all_archs: List[str]):
        new_values: Dict[str, ConfigValue] = {}
        for arch in all_archs:
            value = self.get_value(arch)
            if value != None:
                new_values[arch] = copy.deepcopy(value)
            else:
                new_values[arch] = ConfigValue(self.name, None)
        self.values = new_values

    def set_default_values(self, all_archs: List[str]):
        for arch in all_archs:
            if arch not in self.values:
                self.values[arch] = ConfigValue(self.name, None)

    def write_split_files(self, top_dir: str):
        for arch, value in self.values.items():
            if self.level != "UNKNOWN":
                filename = os.path.join(top_dir, self.level, arch, self.name)
            else:
                filename = os.path.join(top_dir, self.level, self.name, arch, self.name)
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            with open(filename, "w") as f:
                f.write(value.as_string())

    def is_all_empty(self, archs: List[str]) -> bool:
        for arch in archs:
            if arch not in self.values:
                continue
            if self.values[arch].value == None:
                continue
            return False
        return True

    def diff_to_base(self, base: Type["Config"]) -> bool:
        for arch,value in self.values.items():
            if arch not in base.values:
                continue
            if not value.equal(base.values[arch]):
                return True
        return False

    def as_json(self):
        data = {
            "name": self.name,
            "desc": None,
            "level": self.level
        }
        for arch, value in self.values.items():
            data[arch] = value.value
        return data

    @staticmethod
    def empty_instance(name: str, level: str):
        conf = Config(name, level)
        conf.add_value("default", ConfigValue(name, None))
        return conf

    def dump(self):
        print(f"{self.name}  {self.level}")

class Configs():
    configs: Dict[str, Config]
    dist: str
    archs: set

    def __init__(self, dist: str):
        self.configs = {}
        self.dist = dist

    def add_value(self, value: ConfigValue, level: str, arch: str):
        name = value.name
        if name not in self.configs:
            self.configs[name] = Config(name, level)
        self.configs[name].add_value(arch, value)

    def add_values(self, values: ConfigValues, level: str, arch: str):
        for value in values.values:
            self.add_value(value, level, arch)

    def expand_values(self):
        for config in self.configs.values():
            config.expand_values(ConfigRule.arch_list(self.dist))

    def collapse_values(self):
        for config in self.configs.values():
            config.collapse_values(ConfigRule.arch_list(self.dist))

    def set_default_values(self):
        for config in self.configs.values():
            config.set_default_values(ConfigRule.arch_list(self.dist))

    def level_of(self, conf_name: str) -> str:
        if conf_name in self.configs:
            return self.configs[conf_name].level
        return "UNKNOWN"

    def write_split_files(self, top_dir: str):
        for config in self.configs.values():
            config.write_split_files(top_dir)

    def dump(self):
        for config in self.configs.values():
            config.dump()

    def merge_with_override(self, override: Type["Configs"]):
        for config in override.configs.values():
            self.configs[config.name] = copy.deepcopy(config)
        self.dist = override.dist

    def diff_to_base(self, base_configs: Type["Configs"]):
        same_configs: List[Config] = []

        # diff from override to base
        for config in self.configs.values():
            if config.name not in base_configs.configs:
                continue
            if not config.diff_to_base(base_configs.configs[config.name]):
                same_configs.append(config)

        # diff from base to override
        for config in base_configs.configs.values():
            if config.name in self.configs:
                continue
            # avoid write files for follow case:
            # ANCK base: x86 x86-debug are empty, but arm64 arm64-debug has values
            # downstream: only support x86 x86-debug, and they are empty, too
            if config.is_all_empty(ConfigRule.arch_list(self.dist)):
                continue
            self.configs[config.name] = Config.empty_instance(config.name, config.level)

        for config in same_configs:
            del self.configs[config.name]

    def as_json(self):
        data_list = []
        for config in self.configs.values():
            data_list.append(config.as_json())
        return data_list

class Merger():
    """merge all splited files"""
    @staticmethod
    def __merge_from_arch_dirs(top_dir: str, level: str, configs: Configs):
        for arch in os.listdir(top_dir):
            arch_dir = os.path.join(top_dir, arch)
            for conf_name in os.listdir(arch_dir):
                conf_path = os.path.join(arch_dir, conf_name)
                values = ConfigValues.from_config_file(conf_path)
                configs.add_values(values, level, arch)

    @staticmethod
    def __load_configs(path: str, dist: str) -> Configs:
        configs = Configs(dist)
        for level in ConfigRule.levels():
            if ConfigRule.is_override(dist):
                level_dir = os.path.join(path, "OVERRIDE", dist, level)
            else:
                level_dir = os.path.join(path, level)
            if not os.path.exists(level_dir):
                continue
            if level != "UNKNOWN":
                Merger.__merge_from_arch_dirs(level_dir, level, configs)
            else:
                for conf in os.listdir(level_dir):
                    Merger.__merge_from_arch_dirs(os.path.join(level_dir, conf), level, configs)
        return configs

    @staticmethod
    def from_path(path: str, dist: str) -> Configs:
        dist_list = ConfigRule.dist_dependencies(dist)
        dist_list.append(dist)

        configs = None
        for dist in dist_list:
            dist_configs = Merger.__load_configs(path, dist)
            if configs == None:
                configs = dist_configs
            else:
                configs.merge_with_override(dist_configs)

        configs.expand_values()
        return configs

class Generator():
    """generate all config files to build kernel"""
    @staticmethod
    def generate(configs: Configs, top_dir: str, dist: str, arch_list: List[str]):
        kernel_version = ConfigRule.kernel_version()
        for arch in arch_list:
            file_name = f"kernel-{kernel_version}-{arch}-{dist}.config"
            with open(os.path.join(top_dir, file_name), "w") as f:
                for conf_name in sorted(configs.configs):
                    config = configs.configs[conf_name]
                    value = config.get_value(arch)
                    if value is None:
                        continue
                    f.write(value.as_string())
            print(f"* {file_name} generated in {top_dir}")

    @staticmethod
    def do_generate(args):
        dist = ConfigRule.default_dist()
        input_dir = args.input_dir
        output_dir = args.output_dir
        arch_list = args.archs

        configs = Merger.from_path(input_dir, dist)
        Generator.generate(configs, output_dir, dist, arch_list)

class Spliter():
    """split config files into splited files"""
    @staticmethod
    def __parse_configs(config_files: List[str], arch_list: List[str], dist: str, old_configs: Configs) -> Configs:
        configs = Configs(dist)
        for i, file in enumerate(config_files):
            values = ConfigValues.from_config_file(file)
            for value in values.values:
                configs.add_value(value, old_configs.level_of(value.name), arch_list[i])

        configs.set_default_values()
        return configs

    @staticmethod
    def split(config_files: List[str], arch_list: List[str], old_top_dir: str, output_top_dir: str, dist: str):
        base_dist = ConfigRule.dist_dependencies(dist)
        old_dist_configs = Merger.from_path(old_top_dir, dist)
        configs = Spliter.__parse_configs(config_files, arch_list, dist, old_dist_configs)

        if len(base_dist) != 0:
            base_configs = Merger.from_path(old_top_dir, base_dist[-1])
            configs.diff_to_base(base_configs)

        configs.set_default_values()
        configs.collapse_values()
        configs.write_split_files(output_top_dir)

    @staticmethod
    def do_split(args):
        old_top_dir = args.old_top_dir
        output_top_dir = args.output_top_dir
        config_files = args.config_files
        dist = ConfigRule.default_dist()
        kernel_version = ConfigRule.kernel_version()

        archs = []
        for file in config_files:
            file = os.path.basename(file)
            pattern=f'^kernel-{kernel_version}-(.*)-{dist}.config$'
            if not re.match(pattern, file):
                print(f"config file name is illegal: {file}")
                exit(1)
            obj = re.match(pattern, file)
            archs.append(obj.group(1))
        Spliter.split(config_files, archs, old_top_dir, output_top_dir, dist)

class Mover():
    """move configs from old level to new level"""
    @staticmethod
    def get_level(level: str) -> str:
        target_level = ""
        for l in ConfigRule.levels():
            if l.startswith(level):
                if target_level != "":
                    die(f"the level {level} is ambiguous")
                target_level = l

        if target_level == "":
            die(f"unkonw level {level}")
        return target_level

    def conf_name_of(path: str) -> str:
        return os.path.basename(path)

    def conf_arch_of(path: str) -> str:
        return os.path.basename(os.path.dirname(path))

    def is_empty_dir(path: str) -> bool:
        for path in glob.glob(f"{path}/**/*", recursive=True):
            if os.path.isfile(path):
                return False
        return True

    @staticmethod
    def move(old_level: str, new_level: str, conf_patterns: List[str]):
        dist = ConfigRule.default_dist()
        old_level = Mover.get_level(old_level)
        new_level = Mover.get_level(new_level)
        if old_level == new_level:
            exit(0)
        if new_level == "UNKNOWN":
            die("move configs into UNKONWN level is prohibited")

        config_dir = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
        if ConfigRule.is_override(dist):
            config_dir = os.path.join(config_dir, "OVERRIDE", dist)

        level_dir = os.path.join(config_dir, old_level)
        for conf_pattern in conf_patterns:
            config_files = glob.glob(f"{level_dir}/**/{conf_pattern}", recursive=True)
            for conf in config_files:
                if not os.path.isfile(conf):
                    continue
                conf_name = Mover.conf_name_of(conf)
                conf_arch = Mover.conf_arch_of(conf)
                new_path = os.path.join(config_dir, new_level, conf_arch, conf_name)
                print(f"{conf} -> {new_path}")
                shutil.move(conf, new_path)
                if old_level == "UNKNOWN":
                    specific_conf_dir = os.path.join(level_dir, conf_name)
                    if Mover.is_empty_dir(specific_conf_dir):
                        shutil.rmtree(specific_conf_dir)

    @staticmethod
    def do_move(args):
        Mover.move(args.old, args.new_level, args.config_name)

def default_args_func(args):
    pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='process configs')
    parser.set_defaults(func=default_args_func)
    subparsers = parser.add_subparsers()

    generator = subparsers.add_parser('generate', description="generate all files")
    generator.add_argument("--input_dir", required=True, help="the top dir of splited configs")
    generator.add_argument("--output_dir", required=True, help="the output dir to store config files")
    generator.add_argument("archs", nargs="+", help="the archs, eg: x86/x86-debug/arm64/arm64-debug")
    generator.set_defaults(func=Generator.do_generate)

    spliter = subparsers.add_parser('split', description="split configs files into different small files")
    spliter.add_argument("--old_top_dir", required=True, help="the old splited files top dir")
    spliter.add_argument("--output_top_dir", required=True, help="the output new splited files top dir")
    spliter.add_argument("config_files", nargs="+", help="the config files generated by generate cmd")
    spliter.set_defaults(func=Spliter.do_split)

    mover = subparsers.add_parser("move", description="move configs to new level")
    mover.add_argument("--old", default="UNKNOWN", help="the config's old level dir, default is UNKNOWN")
    mover.add_argument("config_name", nargs="+", help="the config name")
    mover.add_argument("new_level", help="the new level")
    mover.set_defaults(func=Mover.do_move)

    args = parser.parse_args()
    args.func(args)