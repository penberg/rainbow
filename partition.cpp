#include <getopt.h>
#include <hwloc.h>
#include <stdio.h>

#include <iostream>

#define DEFAULT_PARTITION_MODE "node"

struct Args
{
  std::string partition_mode = DEFAULT_PARTITION_MODE;
};

static std::string program;

static void
print_opt_error(const std::string& option, const std::string& reason)
{
  std::cerr << program << ": " << reason << " '" << option << "' option" << std::endl;
  std::cerr << "Try '" << program << " --help' for more information" << std::endl;
}

static void
print_unrecognized_opt(const std::string& option)
{
  print_opt_error(option, "unregonized");
}

static void
print_version()
{
  std::cout << "Rainbow 0.0.0" << std::endl;
}

static void
print_usage()
{
  std::cout << "Usage: " << program << " [OPTION]..." << std::endl;
  std::cout << "Start the Sphinx daemon." << std::endl;
  std::cout << std::endl;
  std::cout << "Options:" << std::endl;
  std::cout << "  -P, --partition mode        Partitioning mode. (default: " << DEFAULT_PARTITION_MODE << ")"
            << std::endl;
  std::cout << "      --help                  print this help text and exit" << std::endl;
  std::cout << "      --version               print Sphinx version and exit" << std::endl;
  std::cout << std::endl;
}

static Args
parse_cmd_line(int argc, char* argv[])
{
  static struct option long_options[] = {{"partition_mode", required_argument, 0, 'P'},
                                         {"help", no_argument, 0, 'h'},
                                         {"version", no_argument, 0, 'v'},
                                         {0, 0, 0, 0}};
  Args args;
  int opt, long_index;
  while ((opt = ::getopt_long(argc, argv, "P:hv", long_options, &long_index)) != -1) {
    switch (opt) {
      case 'P':
        args.partition_mode = optarg;
        break;
      case 'h':
        print_usage();
        std::exit(EXIT_SUCCESS);
      case 'v':
        print_version();
        std::exit(EXIT_SUCCESS);
      case '?':
        print_unrecognized_opt(argv[optind - 1]);
        std::exit(EXIT_FAILURE);
      default:
        print_usage();
        std::exit(EXIT_FAILURE);
    }
  }
  return args;
}

hwloc_obj_type_t
parse_partition_type(std::string pm)
{
  if (pm == "machine") {
    return HWLOC_OBJ_MACHINE;
  } else if (pm == "node") {
    return HWLOC_OBJ_NODE;
  } else if (pm == "core") {
    return HWLOC_OBJ_PU;
  }
  throw std::invalid_argument("partition mode is not supported: " + pm);
}

int
main(int argc, char* argv[])
{
  static std::string program;

  auto args = parse_cmd_line(argc, argv);

  hwloc_obj_type_t partition_type = parse_partition_type(args.partition_mode);

  hwloc_topology_t topology;
  hwloc_topology_init(&topology);
  hwloc_topology_load(topology);
  int partition_depth = hwloc_get_type_depth(topology, partition_type);
  if (partition_depth == -1) {
    std::cerr << "warning: No NUMA topology information found. Assuming a UMA system." << std::endl;
    partition_depth = hwloc_get_type_depth(topology, HWLOC_OBJ_MACHINE);
  }
  for (unsigned int i = 0; i < hwloc_get_nbobjs_by_depth(topology, partition_depth); i++) {
    char type[128];
    hwloc_obj_t obj = hwloc_get_obj_by_depth(topology, partition_depth, i);
    hwloc_obj_type_snprintf(type, sizeof(type), obj, 0);
    char* str;
    hwloc_bitmap_asprintf(&str, obj->cpuset);
    printf("Partition %u: type=%s, cpuset=%s\n", i, type, str);
    ::free(str);
  }
  hwloc_topology_destroy(topology);

  return 0;
}
