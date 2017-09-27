#include <stdio.h>
#include <string.h>
#include <opencl.h>

#include "cl_error.h"
#include "slurp.h"

static cl_platform_id platform;
static cl_context context;
static cl_device_id* devices;
static cl_uint device_count;
static unsigned int device_in_use;
static cl_command_queue command_queue;
static cl_mem device_buffer;

static cl_kernel kernel;
static cl_program program;

static unsigned int size;
static unsigned int iterations;

/**
 * Wrapper to help with fetching string-based information about an OpenCL
 * platform.
 *
 * Returns non-null pointer to a string which will need to be passed to free()
 * when finished with.
 * On failure, returns NULL
 */
char *get_platform_info(cl_platform_id id, cl_platform_info value_name)
{
	cl_int ret = 0;
	char *value = NULL;
	size_t value_len = 0;

	ret = clGetPlatformInfo(id, value_name, 0, NULL, &value_len);
	if (ret != CL_SUCCESS) {
		fprintf(stderr, "Failed to get platform info for platform %d: %s\n", id, get_cl_error_string(ret));
		return NULL;
	}

	value = malloc(value_len);
	if (value == NULL) {
		perror("value buffer malloc");
		return NULL;
	}

	ret = clGetPlatformInfo(id, value_name, value_len, value, &value_len);
	if (ret != CL_SUCCESS) {
		fprintf(stderr, "Failed to get platform info for platform %d: %s\n", id, get_cl_error_string(ret));
		return NULL;
	}

	return value;
}

/**
 * Set the trampoline's selected OpenCL platform to the first one with a name
 * matching the one in `preferred_platform`. If no exact match is found,
 * the first available platform is selected instead.
 *
 * Returns 0 when any platform was selected. Returns non-zero if no platform
 * could be selected
 */
int select_platform(const char *preferred_platform)
{
	cl_uint i = 0;
	cl_platform_id *platforms = NULL;
	cl_uint platform_count = 0;
	cl_int ret = 0;
	int preferred_platform_found = 0;
	char *p_name = NULL;
	char *p_vendor = NULL;
	char *p_version = NULL;

	ret = clGetPlatformIDs(0, NULL, &platform_count);
	if (ret != CL_SUCCESS) {
		fprintf(stderr, "Failed to get CL platform count: %s ", get_cl_error_string(ret));
		return 1;
	}

	if (platform_count == 0) {
		fprintf(stderr, "No OpenCL platforms available ");
		return 1;
	}

	platforms = calloc(platform_count, sizeof(cl_platform_id));
	if (platforms == NULL) {
		perror("platform ID array calloc");
		return 1;
	}

	ret = clGetPlatformIDs(platform_count, platforms, NULL);
	if (ret != CL_SUCCESS) {
		fprintf(stderr, "Failed to get CL platform IDs: %s ", get_cl_error_string(ret));
		return 1;
	}

	fprintf(stderr, "\nAvailable platforms:\n");
	for (i = 0; i < platform_count; i++) {
		p_name = get_platform_info(platforms[i], CL_PLATFORM_NAME);
		p_vendor = get_platform_info(platforms[i], CL_PLATFORM_VENDOR);
		p_version = get_platform_info(platforms[i], CL_PLATFORM_VERSION);
		if (   p_name == NULL
		    || p_version == NULL
		    || p_vendor == NULL) {
			free(p_name);
			free(p_vendor);
			free(p_version);
			free(platforms);
			return 1;
		}
		/* Is this platform the first preferred one? Select it for the lovely lady or gentleman */
		if (strcmp(preferred_platform, p_name) == 0 && !preferred_platform_found) {
			platform = platforms[i];
			preferred_platform_found = 1;
		}
		fprintf(stderr, "\t* Platform \"%s\" - From %s (%s)%s\n",
		        p_name, p_vendor, p_version, platform == platforms[i] ? " [SELECTED]" : "" );

		free(p_name);
		free(p_vendor);
		free(p_version);
	}

	if (!preferred_platform_found) {
		fprintf(stderr, "Warning: Preferred platform not found, falling back on first available platform.\n");
		platform = platforms[0];
	}

	free(platforms);

	return 0;
}


/**
 * Initialise the OpenCL trampoline, specifying the name of the OpenCL platform
 * to use if it is available
 *
 * Returns 0 on success, non-zero on failure.
 */
int tramp_init(const char *preferred_platform)
{
	cl_int ret = 0;

	if (select_platform(preferred_platform)) {
		return 1;
	}

	/* FIXME expose device type to user */
	ret = clGetDeviceIDs(platform, CL_DEVICE_TYPE_ALL, 0, NULL, &device_count);
	if (ret != CL_SUCCESS) {
		fprintf(stderr, "Failed to get device count: %s ", get_cl_error_string(ret));
		return 1;
	}

	devices = malloc(device_count * sizeof(cl_device_id));
	if (!devices) {
		perror("device list malloc");
		return 1;
	}

	/* FIXME expose device type to user */
	ret = clGetDeviceIDs(platform, CL_DEVICE_TYPE_ALL, device_count, devices, NULL);
	if (ret != CL_SUCCESS) {
		fprintf(stderr, "Failed to get device ID list: %s ", get_cl_error_string(ret));
		return 1;
	}

	context = clCreateContext(0, 1, devices, NULL, NULL, &ret);
	if (ret != CL_SUCCESS) {
		fprintf(stderr, "Failed to create CL context: %s ", get_cl_error_string(ret));
		return 1;
	}

	/* FIXME expose to user */
	device_in_use = 0;
	command_queue = clCreateCommandQueue(context, devices[device_in_use], 0, &ret);
	if (ret != CL_SUCCESS) {
		fprintf(stderr, "Failed to create command queue on context: %s ", get_cl_error_string(ret));
		return 1;
	}

	return 0;
}

/**
 * Destroy the trampoline, deallocating/freeing resources allocated in a
 * previous call to tramp_init(char*)
 */
void tramp_destroy()
{
	clReleaseKernel(kernel);
	clReleaseProgram(program);
	clReleaseCommandQueue(command_queue);
	clReleaseContext(context);

	if (devices) {
		free(devices);
		devices = NULL;
	}
}

/**
 * Load OpenCL kernel source from the file `filename` and create an OpenCL
 * program from it.
 *
 * Returns 0 on success, non-zero on failure.
 */
int tramp_load_kernel(const char *filename)
{
	cl_int ret = 0;
	size_t length = 0;
	FILE *fin = NULL;
	char *source = NULL;

	fin = fopen(filename, "r");
	if (!fin) {
		perror("fopen");
		return 1;
	}

	source = slurp(fin, &length);
	if (!source)
		return 1;

	fclose(fin);

	program = clCreateProgramWithSource(context, 1, (const char **)&source, &length, &ret);
	if (ret != CL_SUCCESS) {
		fprintf(stderr, "Failed to create program from source code: %s ", get_cl_error_string(ret));
		return 1;
	}

	free(source);
	source = NULL;

	return 0;
}

/**
 * Get a string showing the logged output (if any) of the build stage of OpenCL
 * program compilation.
 *
 * On success, returns a char* which must be passed to free(1) when no longer
 * needed. Else, returns NULL.
 */
char *tramp_get_build_log()
{
	cl_int ret = 0;
	cl_build_status build_status;
	char *build_log = NULL;
	size_t log_size = 0;

	ret = clGetProgramBuildInfo(program, devices[device_in_use],
	                            CL_PROGRAM_BUILD_STATUS,
	                            sizeof(cl_build_status),
	                            &build_status, NULL);

	if (ret != CL_SUCCESS) {
		fprintf(stderr, "Failed to get program build status: %s ", get_cl_error_string(ret));
		return NULL;
	}

	ret = clGetProgramBuildInfo(program, devices[device_in_use],
	                            CL_PROGRAM_BUILD_LOG, 0, NULL, &log_size);
	if (ret != CL_SUCCESS) {
		fprintf(stderr, "Failed to get program build log size: %s ", get_cl_error_string(ret));
		return NULL;
	}

	/* + 1 for null-terminator */
	build_log = malloc(log_size + 1);
	if (!build_log) {
		perror("malloc");
		return NULL;
	}
	ret = clGetProgramBuildInfo(program, devices[device_in_use],
	                            CL_PROGRAM_BUILD_LOG,
	                            log_size, build_log, NULL);
	if (ret != CL_SUCCESS) {
		fprintf(stderr, "Failed to get program build log: %s ", get_cl_error_string(ret));
		return NULL;
	}

	/* null-terminate log */
	build_log[log_size] = '\0';

	return build_log;
}

/**
 * Compile the loaded program/kernel to make it ready for execution.
 *
 * Returns 0 on success, non-zero otherwise.
 */
int tramp_compile_kernel()
{
	cl_int ret = 0;

	ret = clBuildProgram(program, 0, NULL, NULL, NULL, NULL);
	if (ret != CL_SUCCESS) {
		fprintf(stderr, "Failed to build program: %s ", get_cl_error_string(ret));
		return 1;
	}

	kernel = clCreateKernel(program, "fractal_gen", &ret);

	if (ret != CL_SUCCESS) {
		fprintf(stderr, "Failed to create kernel: %s ", get_cl_error_string(ret));
		return 1;
	}

	return 0;
}

/**
 * Set the arguments to be passed to the OpenCL kernel when run on the device.
 *
 * Returns 0 on success, non-zero otherwise.
 *
 * FIXME investigate using something more flexible?
 */
int tramp_set_kernel_args(unsigned int s, unsigned int it)
{
	cl_int ret = 0;

	size = s;
	iterations = it;

	device_buffer = clCreateBuffer(context, CL_MEM_WRITE_ONLY, size*size, NULL, &ret);
	if (ret != CL_SUCCESS) {
		fprintf(stderr, "Failed to create buffer for slave device: %s ", get_cl_error_string(ret));
		return 1;
	}

	ret = clSetKernelArg(kernel, 0, sizeof(cl_mem), &device_buffer);
	if (ret != CL_SUCCESS) {
		fprintf(stderr, "Error on buffer argument: %s ", get_cl_error_string(ret));
		return 1;
	}

	ret = clSetKernelArg(kernel, 1, sizeof(unsigned int), &size);
	if (ret != CL_SUCCESS) {
		fprintf(stderr, "Error on size argument: %s ", get_cl_error_string(ret));
		return 1;
	}

	ret = clSetKernelArg(kernel, 2, sizeof(unsigned long), &iterations);
	if (ret != CL_SUCCESS) {
		fprintf(stderr, "Error on iteration argument: %s ", get_cl_error_string(ret));
		return 1;
	}

	return 0;
}

/**
 * Run the OpenCL kernel on the device with the specified arguments and wait
 * for it to complete execution
 *
 * Returns 0 on success, otherwise 1
 *
 */
int tramp_run_kernel()
{
	cl_event event;
	cl_int ret = 0;
	size_t workgroup_sizes[2];
	workgroup_sizes[0] = size;
	workgroup_sizes[1] = size;

	ret = clEnqueueNDRangeKernel(command_queue, kernel, 2, NULL, workgroup_sizes, NULL, 0, NULL, &event);
	if (ret != CL_SUCCESS) {
		fprintf(stderr, "Failed to enqueue kernel run command: %s ", get_cl_error_string(ret));
		return 1;
	}

	clReleaseEvent(event);
	clFinish(command_queue);

	return 0;
}

/**
 * Copy the data buffer from the device to the host.
 * `buffer` must point to a pointer to a valid location in memory at least
 * `size` bytes large.
 *
 * Returns 0 on success, non-zero otherwise.
 */
int tramp_copy_data(void **buffer, size_t size)
{
	cl_event event;
	cl_int ret = 0;

	ret = clEnqueueReadBuffer(command_queue, device_buffer, CL_TRUE, 0, size, *buffer, 0, NULL, &event);
	if (ret != CL_SUCCESS) {
		fprintf(stderr, "Failed to enqueue read command for data: %s ", get_cl_error_string(ret));
		return 1;
	}
	clReleaseEvent(event);

	return 0;
}
