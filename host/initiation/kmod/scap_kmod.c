/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

/*
 * Copyright (c) 2022-2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <stdint.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_dma.h>
#include <doca_mmap.h>

#include <samples/common.h>

#include "pack.h"
#include "utils.h"

#include "dma_copy_core.h"
#include <linux/ioctl.h>
#include <sys/mman.h>



#define CC_MAX_QUEUE_SIZE 10	   /* Max number of messages on Comm Channel queue */
#define WORKQ_DEPTH 32		   /* Work queue depth */
#define SLEEP_IN_NANOS (10 * 1000) /* Sample the job every 10 microseconds  */
#define STATUS_SUCCESS true	   /* Successful status */
#define STATUS_FAILURE false	   /* Unsuccessful status */

DOCA_LOG_REGISTER(DMA_COPY_CORE);

#define ALIGN_DOWN(n, m)        ((n) / (m) * (m))
#define ALIGN_UP(n, m)  ALIGN_DOWN((n) + (m) - 1, (m))

static void *mmap_reserve(size_t size)
{
        int fd = -1;
        int flags = MAP_ANONYMOUS | MAP_PRIVATE;

        return mmap(0, size, PROT_NONE, flags, fd, 0);
}

static void *mmap_activate(void *ptr, size_t size)
{
        int fd = -1;
        int prot = PROT_READ | PROT_WRITE;
        int flags = MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE;
        void *rc = mmap(ptr, size, prot, flags, fd, 0);
        return rc;
}

static void *ram_mmap(size_t size, size_t align)
{
        size_t offset, total;
        void *ptr, *guardptr;

        total = size + align;

        guardptr = mmap_reserve(total);
        if (guardptr == MAP_FAILED)
                return NULL;

        offset = ALIGN_UP((uint64_t)guardptr, align) - (uint64_t)guardptr;
        ptr = mmap_activate(guardptr + offset, size);
        if (ptr == MAP_FAILED) {
                munmap(guardptr, total);
                return NULL;
        }
        if (offset > 0)
                munmap(guardptr, offset);
        return ptr;
}

/*
 * Validate file size
 *
 * @file_path [in]: File to validate
 * @file_size [out]: File size
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
validate_file_size(const char *file_path, uint32_t *file_size)
{
	FILE *fp;
	long size;

	fp = fopen(file_path, "r");
	if (fp == NULL) {
		DOCA_LOG_ERR("Failed to open %s", file_path);
		return DOCA_ERROR_IO_FAILED;
	}

	if (fseek(fp, 0, SEEK_END) != 0) {
		DOCA_LOG_ERR("Failed to calculate file size");
		fclose(fp);
		return DOCA_ERROR_IO_FAILED;
	}

	size = ftell(fp);
	if (size == -1) {
		DOCA_LOG_ERR("Failed to calculate file size");
		fclose(fp);
		return DOCA_ERROR_IO_FAILED;
	}

	fclose(fp);

	if (size > MAX_DMA_BUF_SIZE) {
		DOCA_LOG_ERR("File size of %ld is larger than DMA buffer maximum size of %d", size, MAX_DMA_BUF_SIZE);
		return DOCA_ERROR_INVALID_VALUE;
	}

	DOCA_LOG_INFO("The file size is %ld", size);

	*file_size = size;

	return DOCA_SUCCESS;
}

/*
 * ARGP validation Callback - check if input file exists
 *
 * @config [in]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
args_validation_callback(void *config)
{
	struct dma_copy_cfg *cfg = (struct dma_copy_cfg *)config;

	if (access(cfg->file_path, F_OK | R_OK) == 0) {
		cfg->is_file_found_locally = true;
		return validate_file_size(cfg->file_path, &cfg->file_size);
	}

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle Comm Channel DOCA device PCI address parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
dev_pci_addr_callback(void *param, void *config)
{
	struct dma_copy_cfg *cfg = (struct dma_copy_cfg *)config;
	const char *dev_pci_addr = (char *)param;

	if (strnlen(dev_pci_addr, DOCA_DEVINFO_PCI_ADDR_SIZE) == DOCA_DEVINFO_PCI_ADDR_SIZE) {
		DOCA_LOG_ERR("Entered device PCI address exceeding the maximum size of %d", DOCA_DEVINFO_PCI_ADDR_SIZE - 1);
		return DOCA_ERROR_INVALID_VALUE;
	}

	strlcpy_doca(cfg->cc_dev_pci_addr, dev_pci_addr, DOCA_DEVINFO_PCI_ADDR_SIZE);

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle file parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
file_path_callback(void *param, void *config)
{
	struct dma_copy_cfg *cfg = (struct dma_copy_cfg *)config;
	char *file_path = (char *)param;
	int file_path_len = strnlen(file_path, MAX_ARG_SIZE);

	if (file_path_len == MAX_ARG_SIZE) {
		DOCA_LOG_ERR("Entered file path exceeded buffer size - MAX=%d", MAX_ARG_SIZE - 1);
		return DOCA_ERROR_INVALID_VALUE;
	}

	strlcpy_doca(cfg->file_path, file_path, MAX_ARG_SIZE);

	return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle Comm Channel DOCA device representor PCI address parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
rep_pci_addr_callback(void *param, void *config)
{
	struct dma_copy_cfg *cfg = (struct dma_copy_cfg *)config;
	const char *rep_pci_addr = (char *)param;

	if (cfg->mode == DMA_COPY_MODE_DPU) {
		if (strnlen(rep_pci_addr, DOCA_DEVINFO_REP_PCI_ADDR_SIZE) == DOCA_DEVINFO_REP_PCI_ADDR_SIZE) {
			DOCA_LOG_ERR("Entered device representor PCI address exceeding the maximum size of %d",
				     DOCA_DEVINFO_REP_PCI_ADDR_SIZE - 1);
			return DOCA_ERROR_INVALID_VALUE;
		}

		strlcpy_doca(cfg->cc_dev_rep_pci_addr, rep_pci_addr, DOCA_DEVINFO_REP_PCI_ADDR_SIZE);
	}

	return DOCA_SUCCESS;
}

/*
 * Wait for status message
 *
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
wait_for_successful_status_msg(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr)
{
	struct cc_msg_dma_status msg_status;
	doca_error_t result;
	size_t msg_len, status_msg_len = sizeof(struct cc_msg_dma_status);
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

	msg_len = status_msg_len;
	while ((result = doca_comm_channel_ep_recvfrom(ep, (void *)&msg_status, &msg_len, DOCA_CC_MSG_FLAG_NONE,
						       peer_addr)) == DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
		msg_len = status_msg_len;
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Status message was not received: %s", doca_get_error_string(result));
		return result;
	}

	if (!msg_status.is_success) {
		DOCA_LOG_ERR("Failure status received");
		return DOCA_ERROR_INVALID_VALUE;
	}

	return DOCA_SUCCESS;
}

/*
 * Send status message
 *
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @status [in]: Status to send
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
send_status_msg(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr, bool status)
{
	struct cc_msg_dma_status status_msg;
	doca_error_t result;
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

	status_msg.is_success = status;

	while ((result = doca_comm_channel_ep_sendto(ep, &status_msg, sizeof(struct cc_msg_dma_status),
						     DOCA_CC_MSG_FLAG_NONE, *peer_addr)) == DOCA_ERROR_AGAIN)
		nanosleep(&ts, &ts);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to send status message: %s", doca_get_error_string(result));
		return result;
	}

	return DOCA_SUCCESS;
}

/*
 * Save remote buffer information into a file
 *
 * @cfg [in]: Application configuration
 * @buffer [in]: Buffer to read information from
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
save_buffer_into_a_file(struct dma_copy_cfg *cfg, const char *buffer)
{
	FILE *fp;

	fp = fopen(cfg->file_path, "w");
	if (fp == NULL) {
		DOCA_LOG_ERR("Failed to create the DMA copy file");
		return DOCA_ERROR_IO_FAILED;
	}

	if (fwrite(buffer, 1, cfg->file_size, fp) != cfg->file_size) {
		DOCA_LOG_ERR("Failed to write full content into the output file");
		fclose(fp);
		return DOCA_ERROR_IO_FAILED;
	}

	fclose(fp);

	return DOCA_SUCCESS;
}

/*
 * Fill local buffer with file content
 *
 * @cfg [in]: Application configuration
 * @buffer [out]: Buffer to save information into
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
fill_buffer_with_file_content(struct dma_copy_cfg *cfg, char *buffer)
{
	FILE *fp;

	fp = fopen(cfg->file_path, "r");
	if (fp == NULL) {
		DOCA_LOG_ERR("Failed to open %s", cfg->file_path);
		return DOCA_ERROR_IO_FAILED;
	}

	/* Read file content and store it in the local buffer which will be exported */
	if (fread(buffer, 1, cfg->file_size, fp) != cfg->file_size) {
		DOCA_LOG_ERR("Failed to read content from file: %s", cfg->file_path);
		fclose(fp);
		return DOCA_ERROR_IO_FAILED;
	}
	fclose(fp);

	return DOCA_SUCCESS;
}

/*
 * Host side function for file size and location negotiation
 *
 * @cfg [in]: Application configuration
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
host_negotiate_dma_direction_and_size(struct dma_copy_cfg *cfg, struct doca_comm_channel_ep_t *ep,
				      struct doca_comm_channel_addr_t **peer_addr)
{
	struct cc_msg_dma_direction host_dma_direction = {0};
	struct cc_msg_dma_direction dpu_dma_direction = {0};
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};
	doca_error_t result;
	size_t msg_len;

	result = doca_comm_channel_ep_connect(ep, SERVER_NAME, peer_addr);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to establish a connection with the DPU: %s", doca_get_error_string(result));
		return result;
	}

	while ((result = doca_comm_channel_peer_addr_update_info(*peer_addr)) == DOCA_ERROR_CONNECTION_INPROGRESS)
		nanosleep(&ts, &ts);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to validate the connection with the DPU: %s", doca_get_error_string(result));
		return result;
	}

	DOCA_LOG_INFO("Connection to DPU was established successfully");

	/* First byte indicates if file is located on Host, other 4 bytes determine file size */
	if (cfg->is_file_found_locally) {
		DOCA_LOG_INFO("File was found locally, it will be DMA copied to the DPU");
		host_dma_direction.file_size = htonl(cfg->file_size);
		host_dma_direction.file_in_host = true;
	} else {
		DOCA_LOG_INFO("File was not found locally, it will be DMA copied from the DPU");
		host_dma_direction.file_in_host = false;
	}

	while ((result = doca_comm_channel_ep_sendto(ep, &host_dma_direction, sizeof(host_dma_direction),
						     DOCA_CC_MSG_FLAG_NONE, *peer_addr)) == DOCA_ERROR_AGAIN)
		nanosleep(&ts, &ts);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to send negotiation buffer to DPU: %s", doca_get_error_string(result));
		return result;
	}

	DOCA_LOG_INFO("Waiting for DPU to send negotiation message");

	msg_len = sizeof(struct cc_msg_dma_direction);
	while ((result = doca_comm_channel_ep_recvfrom(ep, (void *)&dpu_dma_direction, &msg_len,
						       DOCA_CC_MSG_FLAG_NONE, peer_addr)) == DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
		msg_len = sizeof(struct cc_msg_dma_direction);
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Negotiation message was not received: %s", doca_get_error_string(result));
		return result;
	}

	if (msg_len != sizeof(struct cc_msg_dma_direction)) {
		DOCA_LOG_ERR("Negotiation with DPU on file location and size failed");
		return DOCA_ERROR_INVALID_VALUE;
	}

	if (!cfg->is_file_found_locally)
		cfg->file_size = ntohl(dpu_dma_direction.file_size);

	DOCA_LOG_INFO("Negotiation with DPU on file location and size ended successfully");
	return DOCA_SUCCESS;
}

/*
 * Host side function for exporting memory map to DPU side with Comm Channel
 *
 * @core_state [in]: DOCA core structure
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @export_desc [out]: Export descriptor to send
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
host_export_memory_map_to_dpu(struct core_state *core_state, struct doca_comm_channel_ep_t *ep,
			      struct doca_comm_channel_addr_t **peer_addr, const void **export_desc)
{
	doca_error_t result;
	size_t export_desc_len;
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

	/* Export memory map to allow access to this memory region from DPU */
	result = doca_mmap_export_dpu(core_state->mmap, core_state->dev, export_desc, &export_desc_len);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to export DOCA mmap: %s", doca_get_error_string(result));
		return result;
	}

	/* Send the memory map export descriptor to DPU */
	while ((result = doca_comm_channel_ep_sendto(ep, *export_desc, export_desc_len, DOCA_CC_MSG_FLAG_NONE,
						     *peer_addr)) == DOCA_ERROR_AGAIN)
		nanosleep(&ts, &ts);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to send config files to DPU: %s", doca_get_error_string(result));
		return result;
	}

	result = wait_for_successful_status_msg(ep, peer_addr);
	if (result != DOCA_SUCCESS)
		return result;

	return DOCA_SUCCESS;
}

/*
 * Allocate memory and populate it into the memory map
 *
 * @core_state [in]: DOCA core structure
 * @buffer_len [in]: Allocated buffer length
 * @access_flags [in]: The access permissions of the mmap
 * @buffer [out]: Allocated buffer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
memory_alloc_and_populate(struct core_state *core_state, size_t buffer_len, uint32_t access_flags, char *buffer)
{
	doca_error_t result;

	result = doca_mmap_set_permissions(core_state->mmap, access_flags);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set access permissions of memory map: %s", doca_get_error_string(result));
		return result;
	}

	// *buffer = (char *)malloc(buffer_len);
	// if (*buffer == NULL) {
	// 	DOCA_LOG_ERR("Failed to allocate memory for source buffer");
	// 	return DOCA_ERROR_NO_MEMORY;
	// }

	printf("success3\n");

	result = doca_mmap_set_memrange(core_state->mmap, buffer, buffer_len);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set memrange of memory map: %s", doca_get_error_string(result));
		free(buffer);
		return result;
	}

	printf("success4\n");

	/* Populate local buffer into memory map to allow access from DPU side after exporting */
	result = doca_mmap_start(core_state->mmap);
	if (result != DOCA_SUCCESS) {
		printf("successes\n");
		//DOCA_LOG_ERR("Unable to populate memory map: %s", doca_get_error_string(result));
		printf("Unable to populate memory map: %s\n", doca_get_error_string(result));
		free(buffer);
	}

	printf("success5\n");

	return result;
}

/*
 * Host side function to send buffer address and offset
 *
 * @src_buffer [in]: Buffer to send info on
 * @src_buffer_size [in]: Buffer size
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
host_send_addr_and_offset(const char *src_buffer, size_t src_buffer_size, struct doca_comm_channel_ep_t *ep,
			  struct doca_comm_channel_addr_t **peer_addr)
{
	doca_error_t result;
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

	/* Send the full buffer address and length */
	uint64_t addr_to_send = htonq((uintptr_t)src_buffer);
	uint64_t length_to_send = htonq((uint64_t)src_buffer_size);

	while ((result = doca_comm_channel_ep_sendto(ep, &addr_to_send, sizeof(addr_to_send),
						     DOCA_CC_MSG_FLAG_NONE, *peer_addr)) == DOCA_ERROR_AGAIN)
		nanosleep(&ts, &ts);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to send address to start DMA from: %s", doca_get_error_string(result));
		return result;
	}

	result = wait_for_successful_status_msg(ep, peer_addr);
	if (result != DOCA_SUCCESS)
		return result;

	while ((result = doca_comm_channel_ep_sendto(ep, &length_to_send, sizeof(length_to_send),
						     DOCA_CC_MSG_FLAG_NONE, *peer_addr)) == DOCA_ERROR_AGAIN)
		nanosleep(&ts, &ts);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to send config files to DPU: %s", doca_get_error_string(result));
		return result;
	}

	result = wait_for_successful_status_msg(ep, peer_addr);
	if (result != DOCA_SUCCESS)
		return result;

	DOCA_LOG_INFO(
		"Address and offset to start DMA from sent successfully, waiting for DPU to Ack that DMA finished");

	return result;
}

/*
 * DPU side function for file size and location negotiation
 *
 * @cfg [in]: Application configuration
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
dpu_negotiate_dma_direction_and_size(struct dma_copy_cfg *cfg, struct doca_comm_channel_ep_t *ep,
				     struct doca_comm_channel_addr_t **peer_addr)
{
	struct cc_msg_dma_direction host_dma_direction = {0};
	struct cc_msg_dma_direction dpu_dma_direction = {0};
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};
	doca_error_t result;
	size_t msg_len;

	if (cfg->is_file_found_locally) {
		DOCA_LOG_INFO("File was found locally, it will be DMA copied to the Host");
		dpu_dma_direction.file_in_host = false;
		dpu_dma_direction.file_size = htonl(cfg->file_size);
	} else {
		DOCA_LOG_INFO("File was not found locally, it will be DMA copied from the Host");
		dpu_dma_direction.file_in_host = true;
	}

	result = doca_comm_channel_ep_listen(ep, SERVER_NAME);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Comm Channel endpoint couldn't start listening: %s", doca_get_error_string(result));
		return result;
	}

	DOCA_LOG_INFO("Waiting for Host to send negotiation message");

	/* Wait until Host negotiation message will arrive */
	msg_len = sizeof(struct cc_msg_dma_direction);
	while ((result = doca_comm_channel_ep_recvfrom(ep, (void *)&host_dma_direction, &msg_len,
						       DOCA_CC_MSG_FLAG_NONE, peer_addr)) == DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
		msg_len = sizeof(struct cc_msg_dma_direction);
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Response message was not received: %s", doca_get_error_string(result));
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return result;
	}

	if (msg_len != sizeof(struct cc_msg_dma_direction)) {
		DOCA_LOG_ERR("Response negotiation message was not received correctly");
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return DOCA_ERROR_INVALID_VALUE;
	}

	/* Make sure file is located only on one side */
	if (cfg->is_file_found_locally && host_dma_direction.file_in_host == true) {
		DOCA_LOG_ERR("Error - File was found on both Host and DPU");
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return DOCA_ERROR_INVALID_VALUE;

	} else if (!cfg->is_file_found_locally) {
		if (!host_dma_direction.file_in_host) {
			DOCA_LOG_ERR("Error - File was not found on both Host and DPU");
			send_status_msg(ep, peer_addr, STATUS_FAILURE);
			return DOCA_ERROR_INVALID_VALUE;
		}
		cfg->file_size = ntohl(host_dma_direction.file_size);
	}

	/* Send direction message to Host */
	while ((result = doca_comm_channel_ep_sendto(ep, &dpu_dma_direction, sizeof(struct cc_msg_dma_direction),
						     DOCA_CC_MSG_FLAG_NONE, *peer_addr)) == DOCA_ERROR_AGAIN)
		nanosleep(&ts, &ts);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to send negotiation buffer to DPU: %s", doca_get_error_string(result));
		return result;
	}

	return DOCA_SUCCESS;
}

/*
 * DPU side function for clean DOCA core objects
 *
 * @state [in]: DOCA core structure
 */
static void
dpu_cleanup_core_objs(struct core_state *state)
{
	doca_error_t result;

	result = doca_ctx_workq_rm(state->ctx, state->workq);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to remove work queue from ctx: %s", doca_get_error_string(result));

	result = doca_ctx_stop(state->ctx);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Unable to stop DMA context: %s", doca_get_error_string(result));

	result = doca_ctx_dev_rm(state->ctx, state->dev);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to remove device from DMA ctx: %s", doca_get_error_string(result));
}

/*
 * DPU side function for receiving export descriptor on Comm Channel
 *
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @export_desc_buffer [out]: Buffer to save the export descriptor
 * @export_desc_len [out]: Export descriptor length
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
dpu_receive_export_desc(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr,
			char *export_desc_buffer, size_t *export_desc_len)
{
	size_t msg_len;
	doca_error_t result;
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

	DOCA_LOG_INFO("Waiting for Host to send export descriptor");

	/* Receive exported descriptor from Host */
	msg_len = CC_MAX_MSG_SIZE;
	while ((result = doca_comm_channel_ep_recvfrom(ep, (void *)export_desc_buffer, &msg_len,
						       DOCA_CC_MSG_FLAG_NONE, peer_addr)) == DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
		msg_len = CC_MAX_MSG_SIZE;
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to receive export descriptor from Host: %s", doca_get_error_string(result));
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return result;
	}

	*export_desc_len = msg_len;
	DOCA_DLOG_INFO("Export descriptor received successfully from Host");

	result = send_status_msg(ep, peer_addr, STATUS_SUCCESS);
	if (result != DOCA_SUCCESS)
		return result;

	return result;
}

/*
 * DPU side function for receiving remote buffer address and offset on Comm Channel
 *
 * @ep [in]: Comm Channel endpoint
 * @peer_addr [in]: Comm Channel peer address
 * @host_addr [out]: Remote buffer address
 * @host_offset [out]: Remote buffer offset
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
dpu_receive_addr_and_offset(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr,
			    char **host_addr, size_t *host_offset)
{
	doca_error_t result;
	uint64_t received_addr, received_addr_len;
	size_t msg_len;
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

	DOCA_LOG_INFO("Waiting for Host to send address and offset");

	/* Receive remote source buffer address */
	msg_len = sizeof(received_addr);
	while ((result = doca_comm_channel_ep_recvfrom(ep, (void *)&received_addr, &msg_len, DOCA_CC_MSG_FLAG_NONE,
						       peer_addr)) == DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
		msg_len = sizeof(received_addr);
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to receive remote address from Host: %s", doca_get_error_string(result));
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return result;
	}

	received_addr = ntohq(received_addr);
	if (received_addr > SIZE_MAX) {
		DOCA_LOG_ERR("Address size exceeds pointer size in this device");
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return DOCA_ERROR_INVALID_VALUE;
	}
	*host_addr = (char *)received_addr;

	DOCA_DLOG_INFO("Remote address received successfully from Host: %" PRIu64 "", received_addr);

	result = send_status_msg(ep, peer_addr, STATUS_SUCCESS);
	if (result != DOCA_SUCCESS)
		return result;

	/* Receive remote source buffer length */
	msg_len = sizeof(received_addr_len);
	while ((result = doca_comm_channel_ep_recvfrom(ep, (void *)&received_addr_len, &msg_len,
						       DOCA_CC_MSG_FLAG_NONE, peer_addr)) == DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
		msg_len = sizeof(received_addr_len);
	}
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to receive remote address offset from Host: %s", doca_get_error_string(result));
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return result;
	}

	received_addr_len = ntohq(received_addr_len);
	if (received_addr_len > SIZE_MAX) {
		DOCA_LOG_ERR("Offset exceeds SIZE_MAX in this device");
		send_status_msg(ep, peer_addr, STATUS_FAILURE);
		return DOCA_ERROR_INVALID_VALUE;
	}
	*host_offset = (size_t)received_addr_len;

	DOCA_DLOG_INFO("Address offset received successfully from Host: %" PRIu64 "", received_addr_len);

	result = send_status_msg(ep, peer_addr, STATUS_SUCCESS);
	if (result != DOCA_SUCCESS)
		return result;

	return result;
}

/*
 * DPU side function for submitting DMA job into the work queue and save into a file if needed
 *
 * @cfg [in]: Application configuration
 * @core_state [in]: DOCA core structure
 * @bytes_to_copy [in]: Number of bytes to DMA copy
 * @buffer [in]: local DMA buffer
 * @local_doca_buf [in]: local DOCA buffer
 * @remote_doca_buf [in]: remote DOCA buffer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
dpu_submit_dma_job(struct dma_copy_cfg *cfg, struct core_state *core_state, size_t bytes_to_copy, char *buffer,
		   struct doca_buf *local_doca_buf, struct doca_buf *remote_doca_buf)
{
	struct doca_event event = {0};
	struct doca_dma_job_memcpy dma_job = {0};
	doca_error_t result;
	void *data;
	struct doca_buf *src_buf;
	struct doca_buf *dst_buf;
	struct timespec ts = {
		.tv_sec = 0,
		.tv_nsec = SLEEP_IN_NANOS,
	};

	/* Construct DMA job */
	dma_job.base.type = DOCA_DMA_JOB_MEMCPY;
	dma_job.base.flags = DOCA_JOB_FLAGS_NONE;
	dma_job.base.ctx = core_state->ctx;

	/* Determine DMA copy direction */
	if (cfg->is_file_found_locally) {
		src_buf = local_doca_buf;
		dst_buf = remote_doca_buf;
	} else {
		src_buf = remote_doca_buf;
		dst_buf = local_doca_buf;
	}

	/* Set data position in src_buf */
	result = doca_buf_get_data(src_buf, &data);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to get data address from DOCA buffer: %s", doca_get_error_string(result));
		return result;
	}
	result = doca_buf_set_data(src_buf, data, bytes_to_copy);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set data for DOCA buffer: %s", doca_get_error_string(result));
		return result;
	}

	dma_job.src_buff = src_buf;
	dma_job.dst_buff = dst_buf;

	/* Enqueue DMA job */
	result = doca_workq_submit(core_state->workq, &dma_job.base);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(result));
		return result;
	}

	/* Wait for job completion */
	while ((result = doca_workq_progress_retrieve(core_state->workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
	       DOCA_ERROR_AGAIN) {
		nanosleep(&ts, &ts);
	}

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to retrieve DMA job: %s", doca_get_error_string(result));
		return result;
	}

	/* event result is valid */
	result = (doca_error_t)event.result.u64;
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("DMA job event returned unsuccessfully: %s", doca_get_error_string(result));
		return result;
	}

	DOCA_LOG_INFO("DMA copy was done Successfully");

	/* If the buffer was copied into to DPU, save it as a file */
	if (!cfg->is_file_found_locally) {
		DOCA_LOG_INFO("Writing DMA buffer into a file on %s", cfg->file_path);
		result = save_buffer_into_a_file(cfg, buffer);
		if (result != DOCA_SUCCESS)
			return result;
	}

	return result;
}

/*
 * Check if DOCA device is DMA capable
 *
 * @devinfo [in]: Device to check
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t check_dev_dma_capable(struct doca_devinfo *devinfo)
{
	return doca_dma_job_get_supported(devinfo, DOCA_DMA_JOB_MEMCPY);
}

/*
 * Set Comm Channel properties
 *
 * @mode [in]: Running mode
 * @ep [in]: DOCA comm_channel endpoint
 * @dev [in]: DOCA device object to use
 * @dev_rep [in]: DOCA device representor object to use
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
set_cc_properties(enum dma_copy_mode mode, struct doca_comm_channel_ep_t *ep, struct doca_dev *dev, struct doca_dev_rep *dev_rep)
{
	doca_error_t result;

	result = doca_comm_channel_ep_set_device(ep, dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set DOCA device property");
		return result;
	}

	result = doca_comm_channel_ep_set_max_msg_size(ep, CC_MAX_MSG_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set max_msg_size property");
		return result;
	}

	result = doca_comm_channel_ep_set_send_queue_size(ep, CC_MAX_QUEUE_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set snd_queue_size property");
		return result;
	}

	result = doca_comm_channel_ep_set_recv_queue_size(ep, CC_MAX_QUEUE_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set rcv_queue_size property");
		return result;
	}

	if (mode == DMA_COPY_MODE_DPU) {
		result = doca_comm_channel_ep_set_device_rep(ep, dev_rep);
		if (result != DOCA_SUCCESS)
			DOCA_LOG_ERR("Failed to set DOCA device representor property");
	}

	return result;
}

void
destroy_cc(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t *peer,
	   struct doca_dev *dev, struct doca_dev_rep *dev_rep)
{
	doca_error_t result;

	if (peer != NULL) {
		result = doca_comm_channel_ep_disconnect(ep, peer);
		if (result != DOCA_SUCCESS)
			DOCA_LOG_ERR("Failed to disconnect from Comm Channel peer address: %s",
				     doca_get_error_string(result));
	}

	result = doca_comm_channel_ep_destroy(ep);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to destroy Comm Channel endpoint: %s", doca_get_error_string(result));

	if (dev_rep != NULL) {
		result = doca_dev_rep_close(dev_rep);
		if (result != DOCA_SUCCESS)
			DOCA_LOG_ERR("Failed to close Comm Channel DOCA device representor: %s",
				     doca_get_error_string(result));
	}

	result = doca_dev_close(dev);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to close Comm Channel DOCA device: %s", doca_get_error_string(result));
}

doca_error_t
init_cc(struct dma_copy_cfg *cfg, struct doca_comm_channel_ep_t **ep, struct doca_dev **dev,
	struct doca_dev_rep **dev_rep)
{
	doca_error_t result;

	result = doca_comm_channel_ep_create(ep);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create Comm Channel endpoint: %s", doca_get_error_string(result));
		return result;
	}

	result = open_doca_device_with_pci(cfg->cc_dev_pci_addr, NULL, dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open Comm Channel DOCA device based on PCI address");
		doca_comm_channel_ep_destroy(*ep);
		return result;
	}

	/* Open DOCA device representor on DPU side */
	if (cfg->mode == DMA_COPY_MODE_DPU) {
		result = open_doca_device_rep_with_pci(*dev, DOCA_DEV_REP_FILTER_NET, cfg->cc_dev_rep_pci_addr, dev_rep);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to open Comm Channel DOCA device representor based on PCI address");
			doca_comm_channel_ep_destroy(*ep);
			doca_dev_close(*dev);
			return result;
		}
	}

	result = set_cc_properties(cfg->mode, *ep, *dev, *dev_rep);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set Comm Channel properties");
		doca_comm_channel_ep_destroy(*ep);
		if (cfg->mode == DMA_COPY_MODE_DPU)
			doca_dev_rep_close(*dev_rep);
		doca_dev_close(*dev);
	}

	return result;
}

doca_error_t
register_dma_copy_params(void)
{
	doca_error_t result;
	struct doca_argp_param *file_path_param, *dev_pci_addr_param, *rep_pci_addr_param;

	/* Create and register string to dma copy param */
	result = doca_argp_param_create(&file_path_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(file_path_param, "f");
	doca_argp_param_set_long_name(file_path_param, "file");
	doca_argp_param_set_description(file_path_param,
					"Full path to file to be copied/created after a successful DMA copy");
	doca_argp_param_set_callback(file_path_param, file_path_callback);
	doca_argp_param_set_type(file_path_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(file_path_param);
	result = doca_argp_register_param(file_path_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register Comm Channel DOCA device PCI address */
	result = doca_argp_param_create(&dev_pci_addr_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(dev_pci_addr_param, "p");
	doca_argp_param_set_long_name(dev_pci_addr_param, "pci-addr");
	doca_argp_param_set_description(dev_pci_addr_param,
					"DOCA Comm Channel device PCI address");
	doca_argp_param_set_callback(dev_pci_addr_param, dev_pci_addr_callback);
	doca_argp_param_set_type(dev_pci_addr_param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(dev_pci_addr_param);
	result = doca_argp_register_param(dev_pci_addr_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Create and register Comm Channel DOCA device representor PCI address */
	result = doca_argp_param_create(&rep_pci_addr_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
		return result;
	}
	doca_argp_param_set_short_name(rep_pci_addr_param, "r");
	doca_argp_param_set_long_name(rep_pci_addr_param, "rep-pci");
	doca_argp_param_set_description(rep_pci_addr_param,
					"DOCA Comm Channel device representor PCI address (needed only on DPU)");
	doca_argp_param_set_callback(rep_pci_addr_param, rep_pci_addr_callback);
	doca_argp_param_set_type(rep_pci_addr_param, DOCA_ARGP_TYPE_STRING);
	result = doca_argp_register_param(rep_pci_addr_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
		return result;
	}

	/* Register validation callback */
	result = doca_argp_register_validation_callback(args_validation_callback);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program validation callback: %s", doca_get_error_string(result));
		return result;
	}

	/* Register version callback for DOCA SDK & RUNTIME */
	result = doca_argp_register_version_callback(sdk_version_callback);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register version callback: %s", doca_get_error_string(result));
		return result;
	}

	return DOCA_SUCCESS;
}

doca_error_t
open_dma_device(struct doca_dev **dev)
{
	doca_error_t result;

	result = open_doca_device_with_capabilities(check_dev_dma_capable, dev);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to open DOCA DMA capable device");

	return result;
}

doca_error_t
create_core_objs(struct core_state *state, enum dma_copy_mode mode)
{
	doca_error_t result;
	size_t num_elements = 2;

	result = doca_mmap_create(NULL, &state->mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create mmap: %s", doca_get_error_string(result));
		return result;
	}

	if (mode == DMA_COPY_MODE_HOST)
		return DOCA_SUCCESS;

	result = doca_buf_inventory_create(NULL, num_elements, DOCA_BUF_EXTENSION_NONE, &state->buf_inv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create buffer inventory: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_dma_create(&(state->dma_ctx));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create DMA engine: %s", doca_get_error_string(result));
		return result;
	}

	state->ctx = doca_dma_as_ctx(state->dma_ctx);

	result = doca_workq_create(WORKQ_DEPTH, &(state->workq));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create work queue: %s", doca_get_error_string(result));
		return result;
	}

	return result;
}

doca_error_t
init_core_objs(struct core_state *state, struct dma_copy_cfg *cfg)
{
	doca_error_t result;

	result = doca_mmap_dev_add(state->mmap, state->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to add device to mmap: %s", doca_get_error_string(result));
		return result;
	}

	if (cfg->mode == DMA_COPY_MODE_HOST)
		return DOCA_SUCCESS;

	result = doca_buf_inventory_start(state->buf_inv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start buffer inventory: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_ctx_dev_add(state->ctx, state->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to register device with DMA context: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_ctx_start(state->ctx);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start DMA context: %s", doca_get_error_string(result));
		return result;
	}

	result = doca_ctx_workq_add(state->ctx, state->workq);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to register work queue with context: %s", doca_get_error_string(result));
		return result;
	}

	return result;
}

void
destroy_core_objs(struct core_state *state, struct dma_copy_cfg *cfg)
{
	doca_error_t result;

	if (cfg->mode == DMA_COPY_MODE_DPU) {
		result = doca_workq_destroy(state->workq);
		if (result != DOCA_SUCCESS)
			DOCA_LOG_ERR("Failed to destroy work queue: %s", doca_get_error_string(result));
		state->workq = NULL;

		result = doca_dma_destroy(state->dma_ctx);
		if (result != DOCA_SUCCESS)
			DOCA_LOG_ERR("Failed to destroy dma: %s", doca_get_error_string(result));
		state->dma_ctx = NULL;
		state->ctx = NULL;

		result = doca_buf_inventory_destroy(state->buf_inv);
		if (result != DOCA_SUCCESS)
			DOCA_LOG_ERR("Failed to destroy buf inventory: %s", doca_get_error_string(result));
		state->buf_inv = NULL;
	}

	result = doca_mmap_destroy(state->mmap);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to destroy mmap: %s", doca_get_error_string(result));
	state->mmap = NULL;

	result = doca_dev_close(state->dev);
	if (result != DOCA_SUCCESS)
		DOCA_LOG_ERR("Failed to close device: %s", doca_get_error_string(result));
	state->dev = NULL;
}

struct buffer_infor {
	size_t export_desc_len;
	size_t length_to_send;
	char export_desc[2048];
	char *addr_to_send;
};

static doca_error_t
host_send_buffer_infor_to_dpu(struct doca_comm_channel_ep_t *ep, struct doca_comm_channel_addr_t **peer_addr, struct buffer_infor information)
{
	doca_error_t result;
	struct timespec ts = {
		.tv_nsec = SLEEP_IN_NANOS,
	};

	while ((result = doca_comm_channel_ep_sendto(ep, &information, sizeof(information), DOCA_CC_MSG_FLAG_NONE,
						     *peer_addr)) == DOCA_ERROR_AGAIN)
		nanosleep(&ts, &ts);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to send config files to DPU: %s", doca_get_error_string(result));
		return result;
	}

	return DOCA_SUCCESS;
}


// doca_error_t
// host_start_dma_copy(struct dma_copy_cfg *dma_cfg, struct core_state *core_state, struct doca_comm_channel_ep_t *ep,
// 		    struct doca_comm_channel_addr_t **peer_addr)
// {
// 	doca_error_t result;
// 	char *buffer = NULL;
// 	const void *export_desc = NULL;
// 	size_t export_desc_len;

// 	struct buffer_infor buffer_information;


// 	/* Negotiate DMA copy direction with DPU */
// 	result = host_negotiate_dma_direction_and_size(dma_cfg, ep, peer_addr);
// 	if (result != DOCA_SUCCESS)
// 		return result;

// 	/* Allocate memory to be used for read operation in case file is found locally, otherwise grant write access */
// 	uint32_t dpu_access = dma_cfg->is_file_found_locally ? DOCA_ACCESS_DPU_READ_ONLY : DOCA_ACCESS_DPU_READ_WRITE;

// 	result = memory_alloc_and_populate(core_state, dma_cfg->file_size, dpu_access, &buffer);
// 	if (result != DOCA_SUCCESS)
// 		return result;

// 	// /* Export memory map and send it to DPU */
// 	// result = host_export_memory_map_to_dpu(core_state, ep, peer_addr, &export_desc);
// 	// if (result != DOCA_SUCCESS) {
// 	// 	free(buffer);
// 	// 	return result;
// 	// }

// 	// /* Fill the buffer before DPU starts DMA operation */
// 	// if (dma_cfg->is_file_found_locally) {
// 	// 	result = fill_buffer_with_file_content(dma_cfg, buffer);
// 	// 	if (result != DOCA_SUCCESS) {
// 	// 		free(buffer);
// 	// 		return result;
// 	// 	}
// 	// }

// 	// /* Send source buffer address and offset (entire buffer) to enable DMA and wait until DPU is done */
// 	// result = host_send_addr_and_offset(buffer, dma_cfg->file_size, ep, peer_addr);
// 	// if (result != DOCA_SUCCESS) {
// 	// 	free(buffer);
// 	// 	return result;
// 	// }

// 	result = doca_mmap_export_dpu(core_state->mmap, core_state->dev, (void **)&(export_desc), &(export_desc_len));
// 	if (result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Failed to export DOCA mmap: %s", doca_get_error_string(result));
// 		return result;
// 	}

//     memset(buffer, '\0', dma_cfg->file_size / 4);
// 	char* t = buffer;
// 	char* sample;
// 	sample = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
// 	int len_sample = strlen(sample);
// 	while(strlen(buffer) < dma_cfg->file_size / 10240)
// 		{
// 			strcat(t, sample);
// 			t += len_sample;
// 		}


//     memcpy(buffer_information.export_desc, export_desc, export_desc_len);
// 	buffer_information.export_desc_len = export_desc_len;
// 	buffer_information.addr_to_send = buffer;
// 	buffer_information.length_to_send = dma_cfg->file_size;

// 	result = host_send_buffer_infor_to_dpu(ep, peer_addr, buffer_information);
// 	/* Wait to DPU status message to indicate DMA was ended */
// 	result = wait_for_successful_status_msg(ep, peer_addr);
// 	if (result != DOCA_SUCCESS) {
// 		free(buffer);
// 		return result;
// 	}
// 	result = wait_for_successful_status_msg(ep, peer_addr);
// 	if (result != DOCA_SUCCESS) {
// 		free(buffer);
// 		return result;
// 	}
// 	if (!dma_cfg->is_file_found_locally) {
// 		/*  File was copied successfully into the buffer, save it into file */
// 		DOCA_LOG_INFO("Writing DMA buffer into a file on %s", dma_cfg->file_path);
// 		result = save_buffer_into_a_file(dma_cfg, buffer);
// 		if (result != DOCA_SUCCESS) {
// 			free(buffer);
// 			return result;
// 		}
// 	}

// 	free(buffer);
// 	return DOCA_SUCCESS;
// }

void
host_start_dma_copy_sysdig(struct dma_copy_cfg *dma_cfg, struct core_state *core_state, struct doca_comm_channel_ep_t *ep,
		    struct doca_comm_channel_addr_t **peer_addr, char* buffer)
{
	doca_error_t result;
	// char *buffer = NULL;
	const void *export_desc = NULL;
	size_t export_desc_len;

	struct buffer_infor buffer_information;
	
	/* Allocate memory to be used for read operation in case file is found locally, otherwise grant write access */
	uint32_t dpu_access = dma_cfg->is_file_found_locally ? DOCA_ACCESS_DPU_READ_ONLY : DOCA_ACCESS_DPU_READ_WRITE;

	// if (j==0){
	/* Negotiate DMA copy direction with DPU */
	result = host_negotiate_dma_direction_and_size(dma_cfg, ep, peer_addr);

	if (result != DOCA_SUCCESS)
		return result;

	printf("successful communication channel\n");
	// }

	printf("1\n");
	result = memory_alloc_and_populate(core_state, dma_cfg->file_size, dpu_access, buffer);
	if (result != DOCA_SUCCESS)
		return result;
	
	printf("2\n");
	result = doca_mmap_export_dpu(core_state->mmap, core_state->dev, (void **)&(export_desc), &(export_desc_len));
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to export DOCA mmap: %s", doca_get_error_string(result));
		return result;
	}

	printf("3\n");

    //memset(buffer, 'b', 10);

    memcpy(buffer_information.export_desc, export_desc, export_desc_len);
	buffer_information.export_desc_len = export_desc_len;
	buffer_information.addr_to_send = buffer;
	buffer_information.length_to_send = dma_cfg->file_size;


	result = host_send_buffer_infor_to_dpu(ep, peer_addr, buffer_information);
	/* Wait to DPU status message to indicate DMA was ended */
	result = wait_for_successful_status_msg(ep, peer_addr);
	if (result != DOCA_SUCCESS) {
		free(buffer);
		return result;
	}
	//printf("received buffer %d\n",j);

	// sleep(10);
	// memset(buffer, 'a', 10);
	// printf("hello world4\n");
	
	// result = wait_for_successful_status_msg(ep, peer_addr);
	// if (result != DOCA_SUCCESS) {
	// 	free(buffer);
	// 	return result;
	// }
	// printf("hello world4\n");

	if (!dma_cfg->is_file_found_locally) {
		/*  File was copied successfully into the buffer, save it into file */
		DOCA_LOG_INFO("Writing DMA buffer into a file on %s", dma_cfg->file_path);
		result = save_buffer_into_a_file(dma_cfg, buffer);
		if (result != DOCA_SUCCESS) {
			free(buffer);
			return result;
		}
	}

	//free(buffer);

	// return DOCA_SUCCESS;
}

// doca_error_t
// dpu_start_dma_copy(struct dma_copy_cfg *dma_cfg, struct core_state *core_state, struct doca_comm_channel_ep_t *ep,
// 		   struct doca_comm_channel_addr_t **peer_addr)
// {
// 	char *buffer;
// 	char *host_dma_addr = NULL;
// 	char export_desc_buf[CC_MAX_MSG_SIZE];
// 	struct doca_buf *remote_doca_buf;
// 	struct doca_buf *local_doca_buf;
// 	struct doca_mmap *remote_mmap;
// 	size_t host_dma_offset, export_desc_len;
// 	doca_error_t result;

// 	/* Negotiate DMA copy direction with Host */
// 	result = dpu_negotiate_dma_direction_and_size(dma_cfg, ep, peer_addr);
// 	if (result != DOCA_SUCCESS) {
// 		dpu_cleanup_core_objs(core_state);
// 		return result;
// 	}

// 	/* Allocate memory to be used for read operation in case file is found locally, otherwise grant write access */
// 	uint32_t access = dma_cfg->is_file_found_locally ? DOCA_ACCESS_LOCAL_READ_ONLY : DOCA_ACCESS_LOCAL_READ_WRITE;

// 	result = memory_alloc_and_populate(core_state, dma_cfg->file_size, access, &buffer);
// 	if (result != DOCA_SUCCESS) {
// 		dpu_cleanup_core_objs(core_state);
// 		return result;
// 	}

// 	/* Receive export descriptor from Host */
// 	result = dpu_receive_export_desc(ep, peer_addr, export_desc_buf, &export_desc_len);
// 	if (result != DOCA_SUCCESS) {
// 		dpu_cleanup_core_objs(core_state);
// 		free(buffer);
// 		return result;
// 	}

// 	/* Create a local DOCA mmap from export descriptor */
// 	result = doca_mmap_create_from_export(NULL, (const void *)export_desc_buf, export_desc_len,
// 					      core_state->dev, &remote_mmap);
// 	if (result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Failed to create memory map from export descriptor");
// 		dpu_cleanup_core_objs(core_state);
// 		free(buffer);
// 		return result;
// 	}

// 	/* Receive remote address and offset from Host */
// 	result = dpu_receive_addr_and_offset(ep, peer_addr, &host_dma_addr, &host_dma_offset);
// 	if (result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Failed to create memory map from export");
// 		doca_mmap_destroy(remote_mmap);
// 		dpu_cleanup_core_objs(core_state);
// 		free(buffer);
// 		return result;
// 	}

// 	/* Construct DOCA buffer for remote (Host) address range */
// 	result = doca_buf_inventory_buf_by_addr(core_state->buf_inv, remote_mmap, host_dma_addr, host_dma_offset,
// 						&remote_doca_buf);
// 	if (result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Unable to acquire DOCA remote buffer: %s", doca_get_error_string(result));
// 		send_status_msg(ep, peer_addr, STATUS_FAILURE);
// 		doca_mmap_destroy(remote_mmap);
// 		dpu_cleanup_core_objs(core_state);
// 		free(buffer);
// 		return result;
// 	}

// 	/* Construct DOCA buffer for local (DPU) address range */
// 	result = doca_buf_inventory_buf_by_addr(core_state->buf_inv, core_state->mmap, buffer, host_dma_offset,
// 						&local_doca_buf);
// 	if (result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Unable to acquire DOCA local buffer: %s", doca_get_error_string(result));
// 		send_status_msg(ep, peer_addr, STATUS_FAILURE);
// 		doca_buf_refcount_rm(remote_doca_buf, NULL);
// 		doca_mmap_destroy(remote_mmap);
// 		dpu_cleanup_core_objs(core_state);
// 		free(buffer);
// 		return result;
// 	}

// 	/* Fill buffer in file content if relevant */
// 	if (dma_cfg->is_file_found_locally) {
// 		result = fill_buffer_with_file_content(dma_cfg, buffer);
// 		if (result != DOCA_SUCCESS) {
// 			send_status_msg(ep, peer_addr, STATUS_FAILURE);
// 			doca_buf_refcount_rm(local_doca_buf, NULL);
// 			doca_buf_refcount_rm(remote_doca_buf, NULL);
// 			doca_mmap_destroy(remote_mmap);
// 			dpu_cleanup_core_objs(core_state);
// 			free(buffer);
// 			return result;
// 		}
// 	}

// 	/* Submit DMA job into the queue and wait until job completion */
// 	result = dpu_submit_dma_job(dma_cfg, core_state, host_dma_offset, buffer, local_doca_buf, remote_doca_buf);
// 	if (result != DOCA_SUCCESS) {
// 		send_status_msg(ep, peer_addr, STATUS_FAILURE);
// 		doca_buf_refcount_rm(local_doca_buf, NULL);
// 		doca_buf_refcount_rm(remote_doca_buf, NULL);
// 		doca_mmap_destroy(remote_mmap);
// 		dpu_cleanup_core_objs(core_state);
// 		free(buffer);
// 		return result;
// 	}

// 	send_status_msg(ep, peer_addr, STATUS_SUCCESS);

// 	doca_buf_refcount_rm(remote_doca_buf, NULL);
// 	doca_buf_refcount_rm(local_doca_buf, NULL);
// 	doca_mmap_destroy(remote_mmap);
// 	dpu_cleanup_core_objs(core_state);
// 	free(buffer);

// 	return result;
// }
//smart nic########################################################################################################################################################//



#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>

#define SCAP_HANDLE_T struct kmod_engine
#include "kmod.h"
#include "scap.h"
#include "driver_config.h"
#include "../../driver/ppm_ringbuffer.h"
#include "scap-int.h"
#include "scap_engine_util.h"
#include "ringbuffer/ringbuffer.h"
#include "strl.h"
#include "strerror.h"
#include "../../driver/ppm_tp.h"

//#define NDEBUG
#include <assert.h>

// //smartnic//////////////////////////////////////////////

// #include <stdlib.h>
// #include <string.h>

// #include <doca_buf.h>
// #include <doca_buf_inventory.h>
// #include <doca_log.h>

// #include "dma_copy_core.h"

// /////////////////////////////////////////////////////////


static const char * const kmod_kernel_counters_stats_names[] = {
	[KMOD_N_EVTS] = "n_evts",
	[KMOD_N_DROPS_BUFFER_TOTAL] = "n_drops_buffer_total",
	[KMOD_N_DROPS_BUFFER_CLONE_FORK_ENTER] = "n_drops_buffer_clone_fork_enter",
	[KMOD_N_DROPS_BUFFER_CLONE_FORK_EXIT] = "n_drops_buffer_clone_fork_exit",
	[KMOD_N_DROPS_BUFFER_EXECVE_ENTER] = "n_drops_buffer_execve_enter",
	[KMOD_N_DROPS_BUFFER_EXECVE_EXIT] = "n_drops_buffer_execve_exit",
	[KMOD_N_DROPS_BUFFER_CONNECT_ENTER] = "n_drops_buffer_connect_enter",
	[KMOD_N_DROPS_BUFFER_CONNECT_EXIT] = "n_drops_buffer_connect_exit",
	[KMOD_N_DROPS_BUFFER_OPEN_ENTER] = "n_drops_buffer_open_enter",
	[KMOD_N_DROPS_BUFFER_OPEN_EXIT] = "n_drops_buffer_open_exit",
	[KMOD_N_DROPS_BUFFER_DIR_FILE_ENTER] = "n_drops_buffer_dir_file_enter",
	[KMOD_N_DROPS_BUFFER_DIR_FILE_EXIT] = "n_drops_buffer_dir_file_exit",
	[KMOD_N_DROPS_BUFFER_OTHER_INTEREST_ENTER] = "n_drops_buffer_other_interest_enter",
	[KMOD_N_DROPS_BUFFER_OTHER_INTEREST_EXIT] = "n_drops_buffer_other_interest_exit",
	[KMOD_N_DROPS_BUFFER_CLOSE_EXIT] = "n_drops_buffer_close_exit",
	[KMOD_N_DROPS_BUFFER_PROC_EXIT] = "n_drops_buffer_proc_exit",
	[KMOD_N_DROPS_PAGE_FAULTS] = "n_drops_page_faults",
	[KMOD_N_DROPS_BUG] = "n_drops_bug",
	[KMOD_N_DROPS] = "n_drops",
	[KMOD_N_PREEMPTIONS] = "n_preemptions",
};

static struct kmod_engine* alloc_handle(scap_t* main_handle, char* lasterr_ptr)
{
	struct kmod_engine *engine = calloc(1, sizeof(struct kmod_engine));
	if(engine)
	{
		engine->m_lasterr = lasterr_ptr;
	}
	return engine;
}

static void free_handle(struct scap_engine_handle engine)
{
	free(engine.m_handle);
}

static uint32_t get_max_consumers()
{
	uint32_t max;
	FILE *pfile = fopen("/sys/module/" SCAP_KERNEL_MODULE_NAME "/parameters/max_consumers", "r");
	if(pfile != NULL)
	{
		int w = fscanf(pfile, "%"PRIu32, &max);
		if(w == 0)
		{
			fclose(pfile);
			return 0;
		}

		fclose(pfile);
		return max;
	}

	return 0;
}

static int32_t enforce_into_kmod_buffer_bytes_dim(scap_t *handle, unsigned long buf_bytes_dim)
{
	const char* file_name = "/sys/module/" SCAP_KERNEL_MODULE_NAME "/parameters/g_buffer_bytes_dim";

	errno = 0;
	/* Here we check if the dimension provided by the kernel module is the same as the user-provided one.
	 * In this way we can avoid writing under the `/sys/module/...` file.
	 */
	FILE *read_file = fopen(file_name, "r");
	if(read_file == NULL)
	{
		if (errno == ENOENT)
		{
			// It is most probably a wrong API version of the driver;
			// let the issue be gracefully managed during the api version check against the driver.
			return SCAP_SUCCESS;
		}
		return scap_errprintf(handle->m_lasterr, errno, "unable to open '%s'", file_name);
	}

	unsigned long kernel_buf_bytes_dim = 0;
	int ret = fscanf(read_file, "%lu", &kernel_buf_bytes_dim);
	if(ret != 1)
	{
		int err = errno;
		fclose(read_file);
		return scap_errprintf(handle->m_lasterr, err, "unable to read the syscall buffer dim from '%s'", file_name);
	}
	fclose(read_file);

	/* We have no to update the file writing on it, the dimension is the same. */
	if(kernel_buf_bytes_dim == buf_bytes_dim)
	{
		return SCAP_SUCCESS;
	}

	/* Fallback to write on the file if the dim is different */
	FILE *write_file = fopen(file_name, "w");
	if(write_file == NULL)
	{
		return scap_errprintf(handle->m_lasterr, errno, "unable to open '%s'. Probably the /sys/module filesystem is read-only", file_name);
	}

	if(fprintf(write_file, "%lu", buf_bytes_dim) < 0)
	{
		int err = errno;
		fclose(write_file);
		return scap_errprintf(handle->m_lasterr, err, "unable to write into /sys/module/" SCAP_KERNEL_MODULE_NAME "/parameters/g_buffer_bytes_dim");
	}

	fclose(write_file);
	return SCAP_SUCCESS;
}

static int32_t mark_attached_prog(struct kmod_engine* handle, uint32_t ioctl_op, kmod_prog_codes tp)
{
	struct scap_device_set *devset = &handle->m_dev_set;
	if(ioctl(devset->m_devs[0].m_fd, ioctl_op, tp))
	{
		ASSERT(false);
		return scap_errprintf(handle->m_lasterr, errno,
				      "%s(%d) failed for tp %d",
				      __FUNCTION__, ioctl_op, tp);
	}
	return SCAP_SUCCESS;
}

static int32_t mark_syscall(struct kmod_engine* handle, uint32_t ioctl_op, int syscall_id)
{
	struct scap_device_set *devset = &handle->m_dev_set;
	if(ioctl(devset->m_devs[0].m_fd, ioctl_op, syscall_id))
	{
		ASSERT(false);
		return scap_errprintf(handle->m_lasterr, errno,
						"%s(%d) failed for syscall %d",
						__FUNCTION__, ioctl_op, syscall_id);
	}
	return SCAP_SUCCESS;
}

static int enforce_sc_set(struct kmod_engine* handle)
{
	/* handle->capturing == false means that we want to disable the capture */
	bool* sc_set = handle->curr_sc_set.ppm_sc;
	bool empty_sc_set[PPM_SC_MAX] = {0};
	if(!handle->capturing)
	{
		/* empty set to erase all */
		sc_set = empty_sc_set;
	}

	int ret = 0;
	int syscall_id = 0;
	/* Special tracepoints, their attachment depends on interesting syscalls */
	bool sys_enter = false;
	bool sys_exit = false;
	bool sched_prog_fork = false;
	bool sched_prog_exec = false;

	/* We need to enable the socketcall under the hood in case these syscalls are not
	 * defined on the system but we just have the socketcall code.
	 * See https://github.com/falcosecurity/libs/pull/1128
     */
	if(sc_set[PPM_SC_RECV] ||
	   sc_set[PPM_SC_SEND] ||
	   sc_set[PPM_SC_ACCEPT])
	{
		sc_set[PPM_SC_SOCKETCALL] = true;
	}
	else
	{
		sc_set[PPM_SC_SOCKETCALL] = false;
	}

	/* Enforce interesting syscalls */
	for(int sc = 0; sc < PPM_SC_MAX; sc++)
	{
		syscall_id = scap_ppm_sc_to_native_id(sc);
		/* if `syscall_id` is -1 this is not a syscall */
		if(syscall_id == -1)
		{
			continue;
		}

		if(!sc_set[sc])
		{
			ret = ret ?: mark_syscall(handle, PPM_IOCTL_DISABLE_SYSCALL, syscall_id);
		}
		else
		{
			sys_enter = true;
			sys_exit = true;
			ret = ret ?: mark_syscall(handle, PPM_IOCTL_ENABLE_SYSCALL, syscall_id);
			//printf("hello\n");
		}
	}

	if(sc_set[PPM_SC_FORK] ||
	   sc_set[PPM_SC_VFORK] ||
	   sc_set[PPM_SC_CLONE] ||
	   sc_set[PPM_SC_CLONE3])
	{
		sched_prog_fork = true;
	}

	if(sc_set[PPM_SC_EXECVE] ||
	   sc_set[PPM_SC_EXECVEAT])
	{
		sched_prog_exec = true;
	}

	/* Enable desired tracepoints */
	if(sys_enter)
		ret = ret ?: mark_attached_prog(handle, PPM_IOCTL_ENABLE_TP, KMOD_PROG_SYS_ENTER);
	else
		ret = ret ?: mark_attached_prog(handle, PPM_IOCTL_DISABLE_TP, KMOD_PROG_SYS_ENTER);

	if(sys_exit)
		ret = ret ?: mark_attached_prog(handle, PPM_IOCTL_ENABLE_TP, KMOD_PROG_SYS_EXIT);
	else
		ret = ret ?: mark_attached_prog(handle, PPM_IOCTL_DISABLE_TP, KMOD_PROG_SYS_EXIT);

	if(sched_prog_fork)
		ret = ret ?: mark_attached_prog(handle, PPM_IOCTL_ENABLE_TP, KMOD_PROG_SCHED_PROC_FORK);
	else
		ret = ret ?: mark_attached_prog(handle, PPM_IOCTL_DISABLE_TP, KMOD_PROG_SCHED_PROC_FORK);

	if(sched_prog_exec)
		ret = ret ?: mark_attached_prog(handle, PPM_IOCTL_ENABLE_TP, KMOD_PROG_SCHED_PROC_EXEC);
	else
		ret = ret ?: mark_attached_prog(handle, PPM_IOCTL_DISABLE_TP, KMOD_PROG_SCHED_PROC_EXEC);

	if(sc_set[PPM_SC_SCHED_PROCESS_EXIT])
		ret = ret ?: mark_attached_prog(handle, PPM_IOCTL_ENABLE_TP, KMOD_PROG_SCHED_PROC_EXIT);
	else
		ret = ret ?: mark_attached_prog(handle, PPM_IOCTL_DISABLE_TP, KMOD_PROG_SCHED_PROC_EXIT);

	if(sc_set[PPM_SC_SCHED_SWITCH])
		ret = ret ?: mark_attached_prog(handle, PPM_IOCTL_ENABLE_TP, KMOD_PROG_SCHED_SWITCH);
	else
		ret = ret ?: mark_attached_prog(handle, PPM_IOCTL_DISABLE_TP, KMOD_PROG_SCHED_SWITCH);

	if(sc_set[PPM_SC_PAGE_FAULT_USER])
		ret = ret ?: mark_attached_prog(handle, PPM_IOCTL_ENABLE_TP, KMOD_PROG_PAGE_FAULT_USER);
	else
		ret = ret ?: mark_attached_prog(handle, PPM_IOCTL_DISABLE_TP, KMOD_PROG_PAGE_FAULT_USER);

	if(sc_set[PPM_SC_PAGE_FAULT_KERNEL])
		ret = ret ?: mark_attached_prog(handle, PPM_IOCTL_ENABLE_TP, KMOD_PROG_PAGE_FAULT_KERNEL);
	else
		ret = ret ?: mark_attached_prog(handle, PPM_IOCTL_DISABLE_TP, KMOD_PROG_PAGE_FAULT_KERNEL);

	if(sc_set[PPM_SC_SIGNAL_DELIVER])
		ret = ret ?: mark_attached_prog(handle, PPM_IOCTL_ENABLE_TP, KMOD_PROG_SIGNAL_DELIVER);
	else
		ret = ret ?: mark_attached_prog(handle, PPM_IOCTL_DISABLE_TP, KMOD_PROG_SIGNAL_DELIVER);

	return ret;
}

static int32_t scap_kmod_handle_sc(struct scap_engine_handle engine, uint32_t op, uint32_t sc)
{
	struct kmod_engine* handle = engine.m_handle;
	handle->curr_sc_set.ppm_sc[sc] = op == SCAP_PPM_SC_MASK_SET;
	/* We update the system state only if the capture is started */
	if(handle->capturing)
	{
		return enforce_sc_set(handle);
	}
	return SCAP_SUCCESS;
}

int32_t scap_kmod_init(scap_t *handle, scap_open_args *oargs)
{	
	struct scap_engine_handle engine = handle->m_engine;
	struct scap_kmod_engine_params* params  = oargs->engine_params;
	char filename[SCAP_MAX_PATH_SIZE] = {0};
	uint32_t ndevs = 0;
	uint32_t ncpus;
	int32_t rc = 0;

	int mapped_len = 0;
	uint64_t api_version = 0;
	uint64_t schema_version = 0;

	unsigned long single_buffer_dim = params->buffer_bytes_dim;
	if(check_buffer_bytes_dim(handle->m_lasterr, single_buffer_dim) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	/* We need to enforce the buffer dim before opening the devices
	 * otherwise this dimension will be not set during the opening phase!
	 */
	if(enforce_into_kmod_buffer_bytes_dim(handle, single_buffer_dim) != SCAP_SUCCESS)
	{
		return SCAP_FAILURE;
	}

	ncpus = sysconf(_SC_NPROCESSORS_CONF);
	if(ncpus == -1)
	{
		return scap_errprintf(handle->m_lasterr, errno, "_SC_NPROCESSORS_CONF");
	}

	//
	// Find out how many devices we have to open, which equals to the number of CPUs
	//
	ndevs = sysconf(_SC_NPROCESSORS_ONLN);
	if(ndevs == -1)
	{
		return scap_errprintf(handle->m_lasterr, errno, "_SC_NPROCESSORS_ONLN");
	}

	rc = devset_init(&engine.m_handle->m_dev_set, ndevs, handle->m_lasterr);
	if(rc != SCAP_SUCCESS)
	{
		return rc;
	}

	//
	// Allocate the device descriptors.
	//
	// mapped_len = single_buffer_dim * 2;
	mapped_len = single_buffer_dim;
    printf("starting.............");
	printf("hellos");

	size_t new_size = 80 * 1024 *1024;
	size_t aligned_size = 2 * 1024 *1024;
	char * buffer_total;

	buffer_total = ram_mmap(new_size, aligned_size);
	if (!buffer_total) {
        perror("mmap");
        exit(1);
    }
	if (madvise(buffer_total, new_size, MADV_HUGEPAGE)) {
		perror("madvise failed");
		exit(1);
	}

	for (int i = 0; i < new_size; i += 4096) {
		*(volatile char *)(buffer_total + i) = *(buffer_total + i);
	}

	sleep(10);

	//smartnic support
	char* buf;
	doca_error_t result;
	struct dma_copy_cfg dma_cfg = {0};
	struct core_state core_state = {0};
	struct doca_comm_channel_ep_t *ep;
	struct doca_comm_channel_addr_t *peer_addr = NULL;
	struct doca_dev *cc_dev = NULL;
	struct doca_dev_rep *cc_dev_rep = NULL;
	int exit_status = EXIT_SUCCESS;

#ifdef DOCA_ARCH_DPU
	dma_cfg.mode = DMA_COPY_MODE_DPU;
#endif
	
	strcpy(dma_cfg.cc_dev_pci_addr, "3b:00.0");
	//strcpy(dma_cfg.file_path, "/tmp/file_to_create.txt");
	dma_cfg.is_file_found_locally = true;
	dma_cfg.mode = DMA_COPY_MODE_HOST;
	dma_cfg.file_size = MAX_DMA_BUF_SIZE;
	result = init_cc(&dma_cfg, &ep, &cc_dev, &cc_dev_rep);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to Initiate Comm Channel");
		printf("d\n");
		return EXIT_FAILURE;
	}
	/* Open DOCA dma device */
	result = open_dma_device(&core_state.dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open DMA device");
		printf("e\n");
		exit_status = EXIT_FAILURE;
		goto destroy_resources;
	}
	
	/* Create DOCA core objects */
	result = create_core_objs(&core_state, dma_cfg.mode);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create DOCA core structures");
		printf("f\n");
		exit_status = EXIT_FAILURE;
		goto destroy_resources;
	}
	/* Init DOCA core objects */
	result = init_core_objs(&core_state, &dma_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to initialize DOCA core structures");
		printf("g\n");
		exit_status = EXIT_FAILURE;
		goto destroy_resources;
	}

	destroy_resources:
		printf("error happened\n");
	
	host_start_dma_copy_sysdig(&dma_cfg, &core_state, ep, &peer_addr,buffer_total);
    // printf("coming...");


	struct scap_device_set *devset = &engine.m_handle->m_dev_set;
	for(uint32_t j = 0, all_scanned_devs = 0; j < devset->m_ndevs && all_scanned_devs < ncpus; ++all_scanned_devs)
	{
		struct scap_device *dev = &devset->m_devs[j];

		//
		// Open the device
		//
		snprintf(filename, sizeof(filename), "%s/dev/" DRIVER_DEVICE_NAME "%d", scap_get_host_root(), all_scanned_devs);

		if((dev->m_fd = open(filename, O_RDWR | O_SYNC)) < 0)
		{
			if(errno == ENODEV)
			{
				//
				// This CPU is offline, so we just skip it
				//
				continue;
			}
			else if(errno == EBUSY)
			{
				uint32_t curr_max_consumers = get_max_consumers();
				return scap_errprintf(handle->m_lasterr, 0, "Too many consumers attached to device %s. Current value for /sys/module/" SCAP_KERNEL_MODULE_NAME "/parameters/max_consumers is '%"PRIu32"'.", filename, curr_max_consumers);
			}
			else
			{
				return scap_errprintf(handle->m_lasterr, errno, "error opening device %s. Make sure you have root credentials and that the " DRIVER_NAME " module is loaded", filename);
			}
		}

		// Set close-on-exec for the fd
		if (fcntl(dev->m_fd, F_SETFD, FD_CLOEXEC) == -1) {
			int err = errno;
			close(dev->m_fd);
			return scap_errprintf(handle->m_lasterr, err, "Can not set close-on-exec flag for fd for device %s", filename);
		}

		// Check the API version reported
		if (ioctl(dev->m_fd, PPM_IOCTL_GET_API_VERSION, &api_version) < 0)
		{
			int err = errno;
			close(dev->m_fd);
			return scap_errprintf(handle->m_lasterr, err, "Kernel module does not support PPM_IOCTL_GET_API_VERSION");
		}
		// Make sure all devices report the same API version
		if (engine.m_handle->m_api_version != 0 && engine.m_handle->m_api_version != api_version)
		{
			int err = errno;
			close(dev->m_fd);
			return scap_errprintf(handle->m_lasterr, err, "API version mismatch: device %s reports API version %llu.%llu.%llu, expected %llu.%llu.%llu",
					      filename,
					      PPM_API_VERSION_MAJOR(api_version),
					      PPM_API_VERSION_MINOR(api_version),
					      PPM_API_VERSION_PATCH(api_version),
					      PPM_API_VERSION_MAJOR(engine.m_handle->m_api_version),
					      PPM_API_VERSION_MINOR(engine.m_handle->m_api_version),
					      PPM_API_VERSION_PATCH(engine.m_handle->m_api_version)
			);
		}
		// Set the API version from the first device
		// (for subsequent devices it's a no-op thanks to the check above)
		engine.m_handle->m_api_version = api_version;
		//printf("coming3...");

		// Check the schema version reported
		if (ioctl(dev->m_fd, PPM_IOCTL_GET_SCHEMA_VERSION, &schema_version) < 0)
		{
			int err = errno;
			close(dev->m_fd);
			return scap_errprintf(handle->m_lasterr, err, "Kernel module does not support PPM_IOCTL_GET_SCHEMA_VERSION");
		}
		// Make sure all devices report the same schema version
		if (engine.m_handle->m_schema_version != 0 && engine.m_handle->m_schema_version != schema_version)
		{
			return scap_errprintf(handle->m_lasterr, 0, "Schema version mismatch: device %s reports schema version %llu.%llu.%llu, expected %llu.%llu.%llu",
					      filename,
					      PPM_API_VERSION_MAJOR(schema_version),
					      PPM_API_VERSION_MINOR(schema_version),
					      PPM_API_VERSION_PATCH(schema_version),
					      PPM_API_VERSION_MAJOR(engine.m_handle->m_schema_version),
					      PPM_API_VERSION_MINOR(engine.m_handle->m_schema_version),
					      PPM_API_VERSION_PATCH(engine.m_handle->m_schema_version)
			);
		}
		// Set the schema version from the first device
		// (for subsequent devices it's a no-op thanks to the check above)
		engine.m_handle->m_schema_version = schema_version;


	
		//
		// Map the ring buffer
		//
		// dev->m_buffer = (char*)mmap(0,
		// 			     mapped_len,
		// 			     PROT_READ | PROT_WRITE,
		// 			     MAP_PRIVATE,
		// 			     dev->m_fd,
		// 			     0);

		

		// dev->m_buffer = ram_mmap(2 * 1024 *1024, 2 * 1024 *1024);
		// 	if (!dev->m_buffer) {
        // 	perror("mmap");
        // 	exit(1);
    	// }
		// if (madvise(dev->m_buffer, 2 * 1024 *1024, MADV_HUGEPAGE)) {
		// 	perror("madvise failed");
		// 	exit(1);
		// }

		// for (int i = 0; i < 2 * 1024 *1024; i += 4096) {
		// 	*(volatile char *)(dev->m_buffer + i) = *(dev->m_buffer + i);
		// }

		// printf("coming2...");
		dev->m_buffer = buffer_total + j * aligned_size;

		memcpy(dev->m_buffer, "Yes, you are the hero!", 12);
		// sleep(2);

		// if(dev->m_buffer == MAP_FAILED)
		// {
		// 	int err = errno;
		// 	// we cleanup this fd and then we let scap_close() take care of the other ones
		// 	close(dev->m_fd);

		// 	return scap_errprintf(handle->m_lasterr, err, "error mapping the ring buffer for device %s. (If you get memory allocation errors try to reduce the buffer dimension)", filename);
		// }

		if (ioctl(dev->m_fd, MY_IOCTL_COMMAND, (unsigned long)dev->m_buffer) < 0) {
        	perror("IOCTL failed\n");
        	close(dev->m_fd);
        	return 1;
   		}

		// sleep(20);

		// buf = dev->m_buffer;
		// printf("the address 2 is %p\n", buf);
		// printf("buffer is %s\n",buf);
		
		//smartni####################################################################//
		// host_start_dma_copy_sysdig(&dma_cfg, &core_state, ep, &peer_addr,buf,j);

		// /* Destroy Comm Channel */
		// destroy_cc(ep, peer_addr, cc_dev, cc_dev_rep);
		// /* Destroy core objects */
		// destroy_core_objs(&core_state, &dma_cfg);
		// /* ARGP destroy_resources */
		// doca_argp_destroy();
		// printf("Hello, world\n");

		//smartnic############################################


		dev->m_buffer_size = single_buffer_dim;
		dev->m_mmap_size = mapped_len;

		//
		// Map the ppm_ring_buffer_info that contains the buffer pointers
		//
		dev->m_bufinfo = (struct ppm_ring_buffer_info*)mmap(0,
								     sizeof(struct ppm_ring_buffer_info),
								     PROT_READ | PROT_WRITE,
								     MAP_SHARED,
								     dev->m_fd,
								     0);

		if(dev->m_bufinfo == MAP_FAILED)
		{
			int err = errno;

			// we cleanup this fd and then we let scap_close() take care of the other ones
			munmap(dev->m_buffer, mapped_len);
			close(dev->m_fd);

			return scap_errprintf(handle->m_lasterr, err, "error mapping the ring buffer info for device %s. (If you get memory allocation errors try to reduce the buffer dimension)", filename);
		}
		dev->m_bufinfo_size = sizeof(struct ppm_ring_buffer_info);

		++j;
	}
	// printf("sleeping...\n");
	// sleep(30);

	/* Here we are covering the case in which some syscalls don't have an associated ppm_sc
	 * and so we cannot set them as (un)interesting. For this reason, we default them to 0.
	 * Please note this is an extra check since our ppm_sc should already cover all possible syscalls.
	 */
	for(int i = 0; i < SYSCALL_TABLE_SIZE; i++)
	{
		rc = mark_syscall(engine.m_handle, PPM_IOCTL_DISABLE_SYSCALL, i);
		if(rc != SCAP_SUCCESS)
		{
			return rc;
		}
	}	

	/* Store interesting sc codes */
	memcpy(&engine.m_handle->curr_sc_set, &oargs->ppm_sc_of_interest, sizeof(interesting_ppm_sc_set));

	return SCAP_SUCCESS;
}

int32_t scap_kmod_close(struct scap_engine_handle engine)
{
	struct scap_device_set *devset = &engine.m_handle->m_dev_set;

	devset_free(devset);

	return SCAP_SUCCESS;
}

int32_t scap_kmod_next(struct scap_engine_handle engine, OUT scap_evt** pevent, OUT uint16_t* pcpuid)
{
	return ringbuffer_next(&engine.m_handle->m_dev_set, pevent, pcpuid);
}

uint32_t scap_kmod_get_n_devs(struct scap_engine_handle engine)
{
	return engine.m_handle->m_dev_set.m_ndevs;
}

uint64_t scap_kmod_get_max_buf_used(struct scap_engine_handle engine)
{
	return ringbuffer_get_max_buf_used(&engine.m_handle->m_dev_set);
}

//
// Return the number of dropped events for the given handle
//
int32_t scap_kmod_get_stats(struct scap_engine_handle engine, scap_stats* stats)
{
	struct scap_device_set *devset = &engine.m_handle->m_dev_set;
	uint32_t j;

	for(j = 0; j < devset->m_ndevs; j++)
	{
		struct scap_device *dev = &devset->m_devs[j];
		stats->n_evts += dev->m_bufinfo->n_evts;
		stats->n_drops_buffer += dev->m_bufinfo->n_drops_buffer;
		stats->n_drops_buffer_clone_fork_enter += dev->m_bufinfo->n_drops_buffer_clone_fork_enter;
		stats->n_drops_buffer_clone_fork_exit += dev->m_bufinfo->n_drops_buffer_clone_fork_exit;
		stats->n_drops_buffer_execve_enter += dev->m_bufinfo->n_drops_buffer_execve_enter;
		stats->n_drops_buffer_execve_exit += dev->m_bufinfo->n_drops_buffer_execve_exit;
		stats->n_drops_buffer_connect_enter += dev->m_bufinfo->n_drops_buffer_connect_enter;
		stats->n_drops_buffer_connect_exit += dev->m_bufinfo->n_drops_buffer_connect_exit;
		stats->n_drops_buffer_open_enter += dev->m_bufinfo->n_drops_buffer_open_enter;
		stats->n_drops_buffer_open_exit += dev->m_bufinfo->n_drops_buffer_open_exit;
		stats->n_drops_buffer_dir_file_enter += dev->m_bufinfo->n_drops_buffer_dir_file_enter;
		stats->n_drops_buffer_dir_file_exit += dev->m_bufinfo->n_drops_buffer_dir_file_exit;
		stats->n_drops_buffer_other_interest_enter += dev->m_bufinfo->n_drops_buffer_other_interest_enter;
		stats->n_drops_buffer_other_interest_exit += dev->m_bufinfo->n_drops_buffer_other_interest_exit;
		stats->n_drops_buffer_close_exit += dev->m_bufinfo->n_drops_buffer_close_exit;
		stats->n_drops_buffer_proc_exit += dev->m_bufinfo->n_drops_buffer_proc_exit;
		stats->n_drops_pf += dev->m_bufinfo->n_drops_pf;
		stats->n_drops += dev->m_bufinfo->n_drops_buffer +
				  dev->m_bufinfo->n_drops_pf;
		stats->n_preemptions += dev->m_bufinfo->n_preemptions;
	}

	return SCAP_SUCCESS;
}

const struct scap_stats_v2* scap_kmod_get_stats_v2(struct scap_engine_handle engine, uint32_t flags, OUT uint32_t* nstats, OUT int32_t* rc)
{
	struct kmod_engine *handle = engine.m_handle;
	struct scap_device_set *devset = &handle->m_dev_set;
	uint32_t j;
	*nstats = 0;
	scap_stats_v2* stats = handle->m_stats;

	if (!stats)
	{
		*rc = SCAP_FAILURE;
		return NULL;
	}

	if ((flags & PPM_SCAP_STATS_KERNEL_COUNTERS))
	{
		/* KERNEL SIDE STATS COUNTERS */
		for(uint32_t stat = 0; stat < KMOD_MAX_KERNEL_COUNTERS_STATS; stat++)
		{
			stats[stat].type = STATS_VALUE_TYPE_U64;
			stats[stat].flags = PPM_SCAP_STATS_KERNEL_COUNTERS;
			stats[stat].value.u64 = 0;
			strlcpy(stats[stat].name, kmod_kernel_counters_stats_names[stat], STATS_NAME_MAX);
		}

		for(j = 0; j < devset->m_ndevs; j++)
		{
			struct scap_device *dev = &devset->m_devs[j];
			stats[KMOD_N_EVTS].value.u64 += dev->m_bufinfo->n_evts;
			stats[KMOD_N_DROPS_BUFFER_TOTAL].value.u64 += dev->m_bufinfo->n_drops_buffer;
			stats[KMOD_N_DROPS_BUFFER_CLONE_FORK_ENTER].value.u64 += dev->m_bufinfo->n_drops_buffer_clone_fork_enter;
			stats[KMOD_N_DROPS_BUFFER_CLONE_FORK_EXIT].value.u64 += dev->m_bufinfo->n_drops_buffer_clone_fork_exit;
			stats[KMOD_N_DROPS_BUFFER_EXECVE_ENTER].value.u64 += dev->m_bufinfo->n_drops_buffer_execve_enter;
			stats[KMOD_N_DROPS_BUFFER_EXECVE_EXIT].value.u64 += dev->m_bufinfo->n_drops_buffer_execve_exit;
			stats[KMOD_N_DROPS_BUFFER_CONNECT_ENTER].value.u64 += dev->m_bufinfo->n_drops_buffer_connect_enter;
			stats[KMOD_N_DROPS_BUFFER_CONNECT_EXIT].value.u64 += dev->m_bufinfo->n_drops_buffer_connect_exit;
			stats[KMOD_N_DROPS_BUFFER_OPEN_ENTER].value.u64 += dev->m_bufinfo->n_drops_buffer_open_enter;
			stats[KMOD_N_DROPS_BUFFER_OPEN_EXIT].value.u64 += dev->m_bufinfo->n_drops_buffer_open_exit;
			stats[KMOD_N_DROPS_BUFFER_DIR_FILE_ENTER].value.u64 += dev->m_bufinfo->n_drops_buffer_dir_file_enter;
			stats[KMOD_N_DROPS_BUFFER_DIR_FILE_EXIT].value.u64 += dev->m_bufinfo->n_drops_buffer_dir_file_exit;
			stats[KMOD_N_DROPS_BUFFER_OTHER_INTEREST_ENTER].value.u64 += dev->m_bufinfo->n_drops_buffer_other_interest_enter;
			stats[KMOD_N_DROPS_BUFFER_OTHER_INTEREST_EXIT].value.u64 += dev->m_bufinfo->n_drops_buffer_other_interest_exit;
			stats[KMOD_N_DROPS_BUFFER_CLOSE_EXIT].value.u64 += dev->m_bufinfo->n_drops_buffer_close_exit;
			stats[KMOD_N_DROPS_BUFFER_PROC_EXIT].value.u64 += dev->m_bufinfo->n_drops_buffer_proc_exit;
			stats[KMOD_N_DROPS_PAGE_FAULTS].value.u64 += dev->m_bufinfo->n_drops_pf;
			stats[KMOD_N_DROPS].value.u64 += dev->m_bufinfo->n_drops_buffer +
					dev->m_bufinfo->n_drops_pf;
			stats[KMOD_N_PREEMPTIONS].value.u64 += dev->m_bufinfo->n_preemptions;
		}
		*nstats = KMOD_MAX_KERNEL_COUNTERS_STATS;
	}

	*rc = SCAP_SUCCESS;
	return stats;
}

//
// Stop capturing the events
//
int32_t scap_kmod_stop_capture(struct scap_engine_handle engine)
{
	struct kmod_engine* handle = engine.m_handle;
	handle->capturing = false;

	/* This could happen if we fail to instantiate `m_devs` in the init method */
	struct scap_device_set *devset = &engine.m_handle->m_dev_set;
	if(devset->m_devs == NULL)
	{
		return SCAP_SUCCESS;
	}
	return enforce_sc_set(handle);
}

//
// Start capturing the events
//
int32_t scap_kmod_start_capture(struct scap_engine_handle engine)
{
	struct kmod_engine* handle = engine.m_handle;
	handle->capturing = true;
	return enforce_sc_set(handle);
}

static int32_t scap_kmod_set_dropping_mode(struct scap_engine_handle engine, int request, uint32_t sampling_ratio)
{
	struct scap_device_set *devset = &engine.m_handle->m_dev_set;
	if(devset->m_ndevs)
	{
		ASSERT((request == PPM_IOCTL_ENABLE_DROPPING_MODE &&
			((sampling_ratio == 1)  ||
			 (sampling_ratio == 2)  ||
			 (sampling_ratio == 4)  ||
			 (sampling_ratio == 8)  ||
			 (sampling_ratio == 16) ||
			 (sampling_ratio == 32) ||
			 (sampling_ratio == 64) ||
			 (sampling_ratio == 128))) || (request == PPM_IOCTL_DISABLE_DROPPING_MODE));

		if(ioctl(devset->m_devs[0].m_fd, request, sampling_ratio))
		{
			ASSERT(false);
			return scap_errprintf(engine.m_handle->m_lasterr, errno, "%s, request %d for sampling ratio %u",
					      __FUNCTION__, request, sampling_ratio);
		}
	}
	return SCAP_SUCCESS;
}

int32_t scap_kmod_enable_tracers_capture(struct scap_engine_handle engine)
{
	struct scap_device_set *devset = &engine.m_handle->m_dev_set;
	if(devset->m_ndevs)
	{
		{
			if(ioctl(devset->m_devs[0].m_fd, PPM_IOCTL_SET_TRACERS_CAPTURE))
			{
				ASSERT(false);
				return scap_errprintf(engine.m_handle->m_lasterr, errno, "%s failed", __FUNCTION__);
			}
		}
	}

	return SCAP_SUCCESS;
}

int32_t scap_kmod_stop_dropping_mode(struct scap_engine_handle engine)
{
	return scap_kmod_set_dropping_mode(engine, PPM_IOCTL_DISABLE_DROPPING_MODE, 0);
}

int32_t scap_kmod_start_dropping_mode(struct scap_engine_handle engine, uint32_t sampling_ratio)
{
	return scap_kmod_set_dropping_mode(engine, PPM_IOCTL_ENABLE_DROPPING_MODE, sampling_ratio);
}

int32_t scap_kmod_set_snaplen(struct scap_engine_handle engine, uint32_t snaplen)
{
	struct scap_device_set *devset = &engine.m_handle->m_dev_set;
	//
	// Tell the driver to change the snaplen
	//
	if(ioctl(devset->m_devs[0].m_fd, PPM_IOCTL_SET_SNAPLEN, snaplen))
	{
		ASSERT(false);
		return scap_errprintf(engine.m_handle->m_lasterr, errno, "scap_set_snaplen failed");
	}

	uint32_t j;

	//
	// Force a flush of the read buffers, so we don't capture events with the old snaplen
	//
	for(j = 0; j < devset->m_ndevs; j++)
	{
		ringbuffer_readbuf(&devset->m_devs[j],
				   &devset->m_devs[j].m_sn_next_event,
				   &devset->m_devs[j].m_sn_len);

		devset->m_devs[j].m_sn_len = 0;
	}
	return SCAP_SUCCESS;
}

int32_t scap_kmod_handle_dropfailed(struct scap_engine_handle engine, bool enable)
{
	int req = enable ? PPM_IOCTL_ENABLE_DROPFAILED : PPM_IOCTL_DISABLE_DROPFAILED;
	if(ioctl(engine.m_handle->m_dev_set.m_devs[0].m_fd, req))
	{
		ASSERT(false);
		return scap_errprintf(engine.m_handle->m_lasterr, errno, "scap_enable_dynamic_snaplen failed");
	}
	return SCAP_SUCCESS;
}

int32_t scap_kmod_handle_dynamic_snaplen(struct scap_engine_handle engine, bool enable)
{
	//
	// Tell the driver to change the snaplen
	//
	int req = enable ? PPM_IOCTL_ENABLE_DYNAMIC_SNAPLEN : PPM_IOCTL_DISABLE_DYNAMIC_SNAPLEN;
	if(ioctl(engine.m_handle->m_dev_set.m_devs[0].m_fd, req))
	{
		ASSERT(false);
		return scap_errprintf(engine.m_handle->m_lasterr, errno, "scap_enable_dynamic_snaplen failed");
	}
	return SCAP_SUCCESS;
}

int32_t scap_kmod_get_n_tracepoint_hit(struct scap_engine_handle engine, long* ret)
{
	if(ioctl(engine.m_handle->m_dev_set.m_devs[0].m_fd, PPM_IOCTL_GET_N_TRACEPOINT_HIT, ret))
	{
		ASSERT(false);
		return scap_errprintf(engine.m_handle->m_lasterr, errno, "scap_get_n_tracepoint_hit failed");
	}

	return SCAP_SUCCESS;
}

int32_t scap_kmod_set_fullcapture_port_range(struct scap_engine_handle engine, uint16_t range_start, uint16_t range_end)
{
	struct scap_device_set *devset = &engine.m_handle->m_dev_set;
	//
	// Encode the port range
	//
	uint32_t arg = (range_end << 16) + range_start;

	//
	// Beam the value down to the module
	//
	if(ioctl(devset->m_devs[0].m_fd, PPM_IOCTL_SET_FULLCAPTURE_PORT_RANGE, arg))
	{
		ASSERT(false);
		return scap_errprintf(engine.m_handle->m_lasterr, errno, "scap_set_fullcapture_port_range failed");
	}

	uint32_t j;

	//
	// Force a flush of the read buffers, so we don't capture events with the old snaplen
	//
	for(j = 0; j < devset->m_ndevs; j++)
	{
		ringbuffer_readbuf(&devset->m_devs[j],
				   &devset->m_devs[j].m_sn_next_event,
				   &devset->m_devs[j].m_sn_len);

		devset->m_devs[j].m_sn_len = 0;
	}

	return SCAP_SUCCESS;
}

int32_t scap_kmod_set_statsd_port(struct scap_engine_handle engine, const uint16_t port)
{
	struct scap_device_set *devset = &engine.m_handle->m_dev_set;
	//
	// Beam the value down to the module
	//
	if(ioctl(devset->m_devs[0].m_fd, PPM_IOCTL_SET_STATSD_PORT, port))
	{
		ASSERT(false);
		return scap_errprintf(engine.m_handle->m_lasterr,
				      errno, "scap_set_statsd_port: ioctl failed");
	}

	uint32_t j;

	//
	// Force a flush of the read buffers, so we don't
	// capture events with the old snaplen
	//
	for(j = 0; j < devset->m_ndevs; j++)
	{
		ringbuffer_readbuf(&devset->m_devs[j],
				   &devset->m_devs[j].m_sn_next_event,
				   &devset->m_devs[j].m_sn_len);

		devset->m_devs[j].m_sn_len = 0;
	}

	return SCAP_SUCCESS;
}

static int32_t unsupported_config(struct scap_engine_handle engine, const char* msg)
{
	struct kmod_engine* handle = engine.m_handle;

	strlcpy(handle->m_lasterr, msg, SCAP_LASTERR_SIZE);
	return SCAP_FAILURE;
}

static int32_t configure(struct scap_engine_handle engine, enum scap_setting setting, unsigned long arg1, unsigned long arg2)
{
	switch(setting)
	{
	case SCAP_SAMPLING_RATIO:
		if(arg2 == 0)
		{
			return scap_kmod_stop_dropping_mode(engine);
		}
		else
		{
			return scap_kmod_start_dropping_mode(engine, arg1);
		}
	case SCAP_TRACERS_CAPTURE:
		if(arg1 == 0)
		{
			return unsupported_config(engine, "Tracers cannot be disabled once enabled");
		}
		return scap_kmod_enable_tracers_capture(engine);
	case SCAP_SNAPLEN:
		return scap_kmod_set_snaplen(engine, arg1);
	case SCAP_PPM_SC_MASK:
		return scap_kmod_handle_sc(engine, arg1, arg2);
	case SCAP_DROP_FAILED:
		return scap_kmod_handle_dropfailed(engine, arg1);
	case SCAP_DYNAMIC_SNAPLEN:
		return scap_kmod_handle_dynamic_snaplen(engine, arg1);
	case SCAP_FULLCAPTURE_PORT_RANGE:
		return scap_kmod_set_fullcapture_port_range(engine, arg1, arg2);
	case SCAP_STATSD_PORT:
		return scap_kmod_set_statsd_port(engine, arg1);
	default:
	{
		char msg[256];
		snprintf(msg, sizeof(msg), "Unsupported setting %d (args %lu, %lu)", setting, arg1, arg2);
		return unsupported_config(engine, msg);
	}
	}
}

static int32_t scap_kmod_get_threadlist(struct scap_engine_handle engine, struct ppm_proclist_info **procinfo_p, char *lasterr)
{
	struct kmod_engine* kmod_engine = engine.m_handle;
	if(*procinfo_p == NULL)
	{
		if(scap_alloc_proclist_info(procinfo_p, SCAP_DRIVER_PROCINFO_INITIAL_SIZE, lasterr) == false)
		{
			return SCAP_FAILURE;
		}
	}

	int ioctlres = ioctl(kmod_engine->m_dev_set.m_devs[0].m_fd, PPM_IOCTL_GET_PROCLIST, *procinfo_p);
	if(ioctlres)
	{
		if(errno == ENOSPC)
		{
			if(scap_alloc_proclist_info(procinfo_p, (*procinfo_p)->n_entries + 256, kmod_engine->m_lasterr) == false)
			{
				return SCAP_FAILURE;
			}
			else
			{
				return scap_kmod_get_threadlist(engine, procinfo_p, lasterr);
			}
		}
		else
		{
			return scap_errprintf(kmod_engine->m_lasterr, errno, "Error calling PPM_IOCTL_GET_PROCLIST");
		}
	}

	return SCAP_SUCCESS;
}


static int32_t scap_kmod_get_vpid(struct scap_engine_handle engine, uint64_t pid, int64_t* vpid)
{
	struct kmod_engine *kmod_engine = engine.m_handle;
	*vpid = ioctl(kmod_engine->m_dev_set.m_devs[0].m_fd, PPM_IOCTL_GET_VPID, pid);

	if(*vpid == -1)
	{
		ASSERT(false);
		return scap_errprintf(kmod_engine->m_lasterr, errno, "ioctl to get vpid failed");
	}

	return SCAP_SUCCESS;
}

static int32_t scap_kmod_get_vtid(struct scap_engine_handle engine, uint64_t tid, int64_t* vtid)
{
	struct kmod_engine *kmod_engine = engine.m_handle;
	*vtid = ioctl(kmod_engine->m_dev_set.m_devs[0].m_fd, PPM_IOCTL_GET_VTID, tid);

	if(*vtid == -1)
	{
		ASSERT(false);
		return scap_errprintf(kmod_engine->m_lasterr, errno, "ioctl to get vtid failed");
	}

	return SCAP_SUCCESS;
}

int32_t scap_kmod_getpid_global(struct scap_engine_handle engine, int64_t* pid, char* error)
{
	struct kmod_engine *kmod_engine = engine.m_handle;
	*pid = ioctl(kmod_engine->m_dev_set.m_devs[0].m_fd, PPM_IOCTL_GET_CURRENT_PID);
	if(*pid == -1)
	{
		ASSERT(false);
		return scap_errprintf(kmod_engine->m_lasterr, errno, "ioctl to get pid failed");
	}

	return SCAP_SUCCESS;
}

uint64_t scap_kmod_get_api_version(struct scap_engine_handle engine)
{
	return engine.m_handle->m_api_version;
}

uint64_t scap_kmod_get_schema_version(struct scap_engine_handle engine)
{
	return engine.m_handle->m_schema_version;
}

const struct scap_linux_vtable scap_kmod_linux_vtable = {
	.get_vpid = scap_kmod_get_vpid,
	.get_vtid = scap_kmod_get_vtid,
	.getpid_global = scap_kmod_getpid_global,
	.get_threadlist = scap_kmod_get_threadlist,
};

struct scap_vtable scap_kmod_engine = {
	.name = KMOD_ENGINE,
	.mode = SCAP_MODE_LIVE,
	.savefile_ops = NULL,

	.alloc_handle = alloc_handle,
	.init = scap_kmod_init,
	.free_handle = free_handle,
	.close = scap_kmod_close,
	.next = scap_kmod_next,
	.start_capture = scap_kmod_start_capture,
	.stop_capture = scap_kmod_stop_capture,
	.configure = configure,
	.get_stats = scap_kmod_get_stats,
	.get_stats_v2 = scap_kmod_get_stats_v2,
	.get_n_tracepoint_hit = scap_kmod_get_n_tracepoint_hit,
	.get_n_devs = scap_kmod_get_n_devs,
	.get_max_buf_used = scap_kmod_get_max_buf_used,
	.get_api_version = scap_kmod_get_api_version,
	.get_schema_version = scap_kmod_get_schema_version,
};
