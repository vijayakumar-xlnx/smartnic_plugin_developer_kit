// SPDX-License-Identifier: Apache-2.0
// X-SPDX-Copyright-Text: (c) Copyright 2021 Xilinx, Inc.
/** \file xsmartnic_ebpf_api_mc.h API for SmartNIC plugin eBPF programs. */
#ifndef INCLUDED_XSMARTNIC_EBPF_API_MC_H_
#define INCLUDED_XSMARTNIC_EBPF_API_MC_H_
#include <stdint.h>
#include <stdbool.h>

#ifdef __bpf__
#define XNICE_PTR(T)  T*
#else
#define XNICE_PTR(T)  _Alignas(8) uint64_t
#endif

/** Parameter to the plugin extension initialization eBPF function.
 *
 * See plugin extension lifecycle documentation for information about the
 * initialization function. */
struct xnice_plugin_init_md {
  /** Pointer to the first byte of the 'extension extra data'.
   *
   * The size of this is specified in the plugin metadata, and the verifier
   * checks it. */
  XNICE_PTR(void) extension_data;

  /** Unique ID assigned to this plugin which can be used in control capsules'
   * \p cm_engine_id field to identify it. */
  uint8_t engine_id;
};

/** Parameter to plugin control message handler eBPF functions.
 *
 * Message handlers must act upon the contents of #payload. */
struct xnice_plugin_mcmsg_md {
  /** Pointer to the first byte of the 'extension extra data'.
   *
   * The size of this is specified in the plugin metadata, and the verifier
   * checks it. */
  XNICE_PTR(void) extension_data;

  /** Pointer to the first byte of the 'per-handle extra data'.
   *
   * The size of this is specified in the plugin metadata, and the verifier
   * checks it. */
  XNICE_PTR(void) handle_data;

  /** Pointer to the first byte of the message payload passed from the host.
   *
   * The length of this is always exactly as specified in the plugin metadata,
   * and accesses are checked by the verifier. */
  XNICE_PTR(void) payload;

  /** Size (in bytes) of the original request made by the client application.
   *
   * This is always less than or equal to the size specified in the plugin
   * metadata. If it is less then the additional bytes will have been filled
   * with zeros prior to calling the handler, however those additional bytes
   * will still not be passed back to the calling client. This field exists to
   * allow handlers to provide backward-compatibility to clients which are
   * making requests with old (shorter) parameter structs. Compatibility in
   * the other direction (client is newer/longer than handler) must be
   * implemented by the client. */
  uint32_t payload_len;

  /** Unique ID assigned to this plugin which can be used in control capsules'
   * \p cm_engine_id field to identify it. */
  uint8_t engine_id;
};

/** Parameter to plugin resource class destruction eBPF functions.
 *
 * See plugin documentation for details of the lifecycle of resource
 * classes. */
struct xnice_plugin_dtor_md {
  /** Pointer to the first byte of the 'extension extra data'.
   *
   * The size of this is specified in the plugin metadata, and the verifier
   * checks it. */
  XNICE_PTR(void) extension_data;

  /** Pointer to the first byte of the 'per-handle extra data'.
   *
   * The size of this is specified in the plugin metadata, and the verifier
   * checks it. */
  XNICE_PTR(void) handle_data;

  /** Kind of resource being destructed.
   *
   * This is normally not required: each resource class has its own destructor
   * eBPF program, so this value is implied by the specific program being
   * run. */
  uint32_t resource_class;

  /** ID of the resource being destroyed.
   *
   * Identical to #xnice_resource_get_id(this->#resource). */
  uint32_t resource_id;

  /** Instance of the resource being destroyed. */
  XNICE_PTR(struct xnice_resource) resource;

  /** Unique ID assigned to this plugin which can be used in control capsules'
   * \p cm_engine_id field to identify it. */
  uint8_t engine_id;
};

#ifndef DOXYGEN
/* These values define the ABI */
/* Must skip 0, because that'd be the NULL function pointer */
#define XNICE_FUNC_xnice_printf                  1
#define XNICE_FUNC_xnice_lookup_plugin_resource  2
#define XNICE_FUNC_xnice_lookup_vi               3
#define XNICE_FUNC_xnice_lookup_filter           4
#define XNICE_FUNC_xnice_resource_get_id         5
#define XNICE_FUNC_xnice_resource_get_extra      6
#define XNICE_FUNC_xnice_resource_destroy        7
#define XNICE_FUNC_xnice_writel                  8
#define XNICE_FUNC_xnice_readl                   9
#define XNICE_FUNC_xnice_io_barrier              10
#define XNICE_FUNC_xnice_create_plugin_resource  11
#define XNICE_FUNC_xnice_allocate_fpga_dram      12
#define XNICE_FUNC_xnice_allocate_vc             13
#define XNICE_FUNC_xnice_vi_set_routing          14
#define XNICE_FUNC_xnice_mac_set_routing         15
#define XNICE_FUNC_xnice_host_set_routing        16
#define XNICE_FUNC_xnice_is_admin                17
#define XNICE_FUNC_xnice_cam_reset               19
#define XNICE_FUNC_xnice_cam_insert              20
#define XNICE_FUNC_xnice_cam_update              21
#define XNICE_FUNC_xnice_cam_delete              22
#define XNICE_FUNC_xnice_cam_lookup              23
#define XNICE_FUNC_xnice_cam_get_by_key          24
#define XNICE_FUNC_xnice_readq_counter           25
#define XNICE_FUNC_xnice_readl_wait              26
#endif

/** Comparison operator to use with xnice_readl_wait(). */
enum xnice_comparison_op {
  XNICE_CMP_EQ,    /**< Compare for equality */
  XNICE_CMP_NEQ,   /**< Compare for inequality */
};

/** Defines the range of objects to be affected by an operation */
enum xnice_scope {
  /** Affect every object in the system.
   *
   * This scope is typically used when the plugin implements its own filtering
   * internally */
  XSN_SCOPE_ALL = 0,
  /** Affect objects owned by any host interface */
  XSN_SCOPE_HOST = 1,
  /** Affect objects owned by the on-chip SoC */
  XSN_SCOPE_INT_SOC = 2,
  /** Affect objects owned by the on-card SoC */
  XSN_SCOPE_EXT_SOC = 3,
  /** Affect only the objects owned by the calling client or any of its
   * descendant clients */
  XSN_SCOPE_CLIENT_AND_DESCENDANTS = 4,
  /** Affect the objects owned by the calling client only */
  XSN_SCOPE_CLIENT = 5,
};

/** Flags for use with xnice_resource_destroy() */
enum xnice_resource_destroy_flags {
  /** Do not run the resource class destructor eBPF program.
   *
   * See xnice_resource_destroy() for additional details of the semantics. */
  XSN_DESTROY_SKIP_DTOR = 0x0001,
};

/** Describes an area of memory allocated by xnice_allocate_fpga_dram() */
struct xnice_memory_region {
  /** Location of the allocated region.
   *
   * This pointer is appropriate for direct use in DMA descriptors, and can be
   * passed to the plugin for access through the DDR controller(s). */
  uint64_t base_ptr;

  /** Actual number of bytes which were allocated (always >=num_bytes). */
  uint64_t actual_bytes;

  /** Address space ID suitable for being passed back to the host for
   * (e.g.) later mem2mem transfers. */
  uint64_t addr_spc_id;
};

#ifdef __bpf__
#ifdef DOXYGEN
#define XNICE_HELPER(Ret, Name, Args) Ret Name Args
#else
#define XNICE_HELPER(Ret, Name, Args) static Ret (* const Name)Args \
                                          = (Ret (*)Args)XNICE_FUNC_##Name
#endif

/** Opaque handle to a resource, both plugin-specific resource types and
 * built-in NIC resources. */
struct xnice_resource;

/** Opaque handle to a Content Addressable Memory instance.
 *
 * Instances of this struct should be defined within the source eBPF as:
 * \code
 *   extern struct xnice_cam MY_CAM_NAME;
 * \endcode
 * where "MY_CAM_NAME" is matched by the compilation toolchain against the
 * name used in the plugin's source code. */
struct xnice_cam;

/** Print a debugging message to the log.
 *
 * An implicit linefeed is added after the message.
 *
 * This function is modelled after printf, however the eBPF environment
 * enforces significant limitations on its capabilities:
 * - The format string must be a compile-time constant
 * - At most 4 additional parameters are supported
 * - The %-specifier sets are very limited
 * - The format string may not contain any non-ASCII characters. This includes
 *   \\n and \\t.
 *
 * The following format specifiers are available:
 * - %d/%i/%u/%x: print integers in the standard manner. The fact that they
 *   are scalars is verified.
 * - %%: a literal percent.
 *
 * The only format qualifiers supported are "l" and "ll", for the integral
 * format specifiers. No width specifiers or other modifiers are allowed. This
 * is verified.
 *
 * Returns the number of characters written to the log.
 */
XNICE_HELPER(int, xnice_printf, (const char* fmt, ...));

/** Validates and looks-up a pre-existing resource ID of the given class.
 *
 * If \a referrer is non-NULL then a new edge in the dependency DAG is created
 * from the referrer to the looked-up resource, i.e. if the looked-up resource
 * is destroyed then referrer will be too (but not vice-versa). \a referrer is
 * verified to be a plugin resource and must be of a resource class number
 * strictly greater than the value of the resource_class argument; this is to
 * enforce statically that there are no circular dependencies.
 *
 * It is a verifier error if resource_class is invalid or does not evaluate
 * to a constant. Returns NULL if no such resource exists, or if the calling
 * context does not have permission to access it.
 */
XNICE_HELPER(struct xnice_resource*, xnice_lookup_plugin_resource,
              (void *ctx, int resource_class, int id,
               struct xnice_resource* referrer));

/** Validates and looks-up a pre-existing VI by its ID.
 *
 * The \a vi_id used as a parameter to this function is a 'relative' VI number,
 * which are the types of number presented to each host device/VM. To get a
 * number which is meaningful to the slice plugin (i.e. \p src_qid or
 * \p dst_qid in the capsule metadata), use xnice_resource_get_id() on the
 * return value from this function.
 *
 * See xnice_lookup_plugin_resource() for the behaviour of the \a referrer
 * parameter.
 *
 * Returns NULL if no such VI exists, or if the calling context does not
 * have permission to access it.
 */
XNICE_HELPER(struct xnice_resource*, xnice_lookup_vi,
              (void *ctx, int vi_id, struct xnice_resource* referrer));

#if 0
/** Validates and looks-up a pre-existing routing filter by its ID.
 *
 * See xnice_lookup_plugin_resource() for the behaviour of the \a referrer
 * parameter.
 *
 * Returns NULL if no such filter exists, or if the calling context does not
 * have permission to access it.
 */
XNICE_HELPER(struct xnice_resource*, xnice_lookup_filter,
              (void *ctx, int filter_id, struct xnice_resource* referrer));
#endif

/** Returns the ID of the given resource, as a number meaningful to the MC.
 *
 * All types of resource have an ID, however in some cases those IDs are not
 * particularly useful.
 *
 * This function cannot fail. \a resource is verified to be non-NULL.
 */
__attribute__((const))
XNICE_HELPER(int, xnice_resource_get_id, (struct xnice_resource* resource));

/** Returns a pointer to the first byte of 'extra' resource data.
 *
 * The plugin's metadata may request n bytes of additional storage space be
 * allocated for every resource of a given class. This can be used for any
 * purpose by the plugin's eBPF code.
 *
 * This function cannot fail. \a resource is verified to be a plugin resource
 * of a class which has a non-zero amount of extra space.
 */
__attribute__((const))
XNICE_HELPER(void*, xnice_resource_get_extra,
             (struct xnice_resource* resource));

/** Destroy an existing resource.
 *
 * The resource is verified to be a plugin resource. Since the dependency
 * graph may cause arbitrary other resources to be destroyed, the verifier
 * will mark all tracked xnice_resource instances as invalid upon executing
 * this call: they must all be looked-up again.
 *
 * Note that this function can run destructor eBPF programs, which may modify
 * FPGA state and service-global extra data. Users should be cognizant of the
 * reentrancy issues.
 *
 * If the flag #XSN_DESTROY_SKIP_DTOR is used then the destructor eBPF for the
 * given resource will not be executed before the allocation is destroyed.
 * This is typically used on error-handling paths when the resource has just
 * been constructed but the hardware hasn't been informed yet - in that case
 * the hardware shouldn't be told of the removal of something which was never
 * created. This flag only affects the specified resource; if other dependent
 * resources are automatically removed then their destructors will be run as
 * normal.
 *
 * This function cannot fail.
 */
XNICE_HELPER(void, xnice_resource_destroy, (struct xnice_resource* resource,
                                      unsigned flags));

/** Writes to a register over the plugin's AXI-Lite control bus.
 *
 * The plugin may have its register window mapped at an arbitrary address in
 * the MC's address space, however to this function it will always appear as
 * though the window starts at address 0.
 *
 * It is a verifier error if \a addr is out of range of the plugin's register
 * window. */
XNICE_HELPER(void, xnice_writel, (uint32_t addr, uint32_t value));

/** Reads from a register over the plugin's AXI-Lite control bus.
 *
 * The plugin may have its register window mapped at an arbitrary address in
 * the MC's address space, however to this function it will always appear as
 * though the window starts at address 0.
 *
 * It is a verifier error if \a addr is out of range of the plugin's register
 * window. */
XNICE_HELPER(uint32_t, xnice_readl, (uint32_t addr));

/** Reads a 64-bit register over the plugin's AXI-Lite control bus.
 *
 * The AXI-Lite bus supports only 32-bit accesses, so this function runs a loop
 * reading each half of the 64-bit value until a stable value is obtained. This
 * loop may give incorrect answers if the actual value is not monotonically
 * increasing or decreasing. If the loop runs for too many iterations without
 * finding a untorn value then this function returns false. In any case,
 * *value is always assigned the last value read.
 *
 * It is a verifier error if \a low_addr or \a high_addr is out of range of
 * the plugin's register window. */
XNICE_HELPER(bool, xnice_readq_counter, (uint32_t low_addr, uint32_t high_addr,
                                   uint64_t *value));

/** Reads from a status register over the plugin's AXI-Lite control bus, waiting
 * for a specific value.
 *
 * This function runs xnice_readl() in a loop waiting until
 * <tt>(readl() & mask) \<op> expected</tt>. It is typically used to wait for
 * hardware to acknowledge completion of a request or readiness for another
 * command.
 *
 * This function will loop for at most \a timeout_ns nanoseconds. If the
 * timeout expires before \a expected is seen then the function returns false.
 * In any case, the last value returned from readl() is assigned to
 * <tt>*value</tt>. \a value may be NULL if this data is not wanted. In all
 * cases (i.e. if \a timeout_ns is zero), at least one loop iteration will
 * always be performed.
 *
 * The runtime environment imposes a total cap of 50 microseconds on the sum of
 * all waits executed in an entire handler's execution. If this cap is exceeded
 * then any further xnice_readl_wait() calls will have their \a timeout_ns
 * clamped to zero and thus will typically return false.
 *
 * It is a verifier error if \a addr is out of range of the plugin's register
 * window. */
__attribute__((always_inline))
static inline bool xnice_readl_wait(void *ctx, uint32_t addr, uint32_t mask,
                                enum xnice_comparison_op op, uint32_t expected,
                                uint32_t *value, uint32_t timeout_ns)
{
  typedef bool impl_t(void*, uint32_t, uint64_t, uint64_t, uint32_t*);
  impl_t *impl = (impl_t*)XNICE_FUNC_xnice_readl_wait;
  return impl(ctx, addr, mask | ((uint64_t)expected << 32),
              timeout_ns | ((uint64_t)op << 32), value);
}

/** Inserts a barrier instruction in to the stream.
 *
 * This helper function must be used after an xnice_writel() and before a
 * following xnice_readl() if the results of the read are to reflect the
 * previously-written register.
 *
 * Note that on some cards this function may be a no-op, but this is not
 * guaranteed to be the case everywhere so plugin authors must always use
 * it between writes and dependent subsequent reads. */
XNICE_HELPER(void, xnice_io_barrier, (void));

/** Creates an (opaque) object which references some type of generic plugin
 * resource.
 *
 * Unlike the sfc_char equivalent, this function creates both the handle and
 * allocates an instance ID. Plugin resource instances have IDs contiguously
 * allocated starting at 0. The maximum number permitted is defined in the
 * plugin metadata, therefore (if successful) this function will always
 * return an object with an ID in the range [0, max). Use
 * xnice_resource_get_id() to obtain the allocated ID.
 *
 * It is a verifier error if resource_class is invalid or does not evaluate
 * to a constant. If \p max instances of this resource class have already
 * been allocated then this function returns NULL.
 */
XNICE_HELPER(struct xnice_resource*, xnice_create_plugin_resource,
              (void* ctx, int resource_class));

/** Allocates a contiguous region of the on-chip DDR memory.
 *
 * A reference is created from \a referrer to the allocated region, i.e. if
 * \a referrer is destroyed then the memory is freed. \a referrer is verified
 * to be a plugin resource and may not be NULL.
 *
 * \a bank is a bitmask of the memory controller(s) through which the plugin
 * will access the memory. If multiple bits are given then it is the plugin's
 * responsibility to check from which bank the memory actually got allocated
 * and hence use the correct controller. The function will fail (-EINVAL) if
 * 0 is passed. It is not an error to set bits which do not exist on the
 * current hardware platform - the additional bits will be ignored.
 *
 * The location of the allocated region is written to \a result.
 *
 * Returns 0 on success or a negative error code (typically -ENOMEM when there
 * is no free space).
 */
XNICE_HELPER(int, xnice_allocate_fpga_dram,
              (uint64_t num_bytes, struct xnice_memory_region *result,
               unsigned bank, struct xnice_resource* referrer));

#if 0
/** Allocates a virtual channel for the plugin's use.
 *
 * Virtual channels are a very limited resource (64 total on current
 * architectures) so plugins should limit their use. This function is
 * typically only called by the service initialisation eBPF programme.
 *
 * A reference is created from \a referrer to the allocated region, i.e. if
 * \a referrer is destroyed then the memory is freed. \a referrer is verified
 * to be either NULL or a plugin resource. If it is NULL then the VC will
 * remain allocated to the plugin until the plugin is unloaded, with no way to
 * free it.
 *
 * Returns the VC ID on success (a value in the range [0,63)), or a negative
 * error value (-ENOSPC if no VCs are available).
 */
XNICE_HELPER(int, xnice_alloc_vc, (struct xnice_resource* referrer));
#endif

/** Streaming subsystem capsule routing configuration.
 *
 * For use by xnice_vi_set_routing(), xnice_mac_set_routing() and
 * xnice_host_set_routing(). */
enum xnice_ch_route_bits {
  /** Route packets at hub A to socket H2P */
  XSN_CH_ROUTE_HUB_A_PL = 0x08,
  /** Route packets at hub B to sockets VNT2P and NRX2P */
  XSN_CH_ROUTE_HUB_B_PL = 0x10,
  /** Route packets at hub C to sockets HMAE2P and NMAE2P */
  XSN_CH_ROUTE_HUB_C_PL = 0x20,
  /** Route packets at hub D to socket VNR2P */
  XSN_CH_ROUTE_HUB_D_PL = 0x40,
};

/** Calls the DMAC to modify the default capsule routing bits for the given VI.
 *
 * This function is used to ensure that packets sent from the host over a
 * specific VI are directed to the correct slice plugin sockets as required
 * by the plugin's functionality. Any previously-set routing bits for the VI
 * are replaced with those specified in the call to this function.
 *
 * \a vi is verified to be a VI resource. \a ch_route is the bitwise OR of
 * #xnice_ch_route_bits, and is verified not to contain any unknown bits.
 *
 * Returns zero on success, or a negative error value (-ENOSPC if no
 * ch_route-table entries are available).
 */
XNICE_HELPER(int, xnice_vi_set_routing,
             (void *ctx, struct xnice_resource* vi, unsigned ch_route));

/** Modifies the default capsule routing bits for packets from the network.
 *
 * This function is used to ensure that packets sent from the network are
 * directed to the correct slice plugin sockets as required by the plugin's
 * functionality. This function is typically called by the service initialiser
 * eBPF programme. Any previously-set routing bits for the port(s) are replaced
 * with those specified in the call to this function.
 *
 * Multiple independent plugins may request a change to the routing, in which
 * case the actual applied routing is the bitwise OR of the routing bits set
 * by all currently-loaded plugins.
 *
 * \a ch_route is the bitwise OR of #xnice_ch_route_bits, and is verified not
 * to contain any unknown bits. \a port must be a valid port number on this
 * card (port numbers start at 0) or the value -1 to change the routing bits
 * for all ports. If any other value is used then the call fails. This is a
 * bug in the eBPF programme. \a pcp is the Priority Code Point to match from
 * the outermost VLAN ID; like port, it may be -1 to affect every PCP on the
 * requested port(s) or a value 0-7.
 *
 * Returns zero on success, or a negative error value (-ERANGE if the port is
 * out of range).
 */
XNICE_HELPER(int, xnice_mac_set_routing,
             (void *ctx, int port, int pcp, unsigned ch_route));

/** Calls the DMAC to modify the default capsule routing for multiple VIs
 *
 * See also xnice_vi_set_routing(). This function sets the routing for a set of
 * VIs; that set is defined dynamically by the rules set by this function, i.e.
 * when VIs are added or removed from the set then their routing bits are
 * automatically adjusted correspondingly. If a VI is subject to multiple
 * rules, either set by this function or by this function and
 * xnice_vi_set_routing(), then its resultant routing bits are the bitwise OR
 * of all rules.
 *
 * \a scope defines which VIs are to be affected by this call, relative to the
 * client which sent the plugin message currently being processed. A ch_route
 * value is stored independently at each scope; calling this function again
 * when a ch_route has already been set at the given scope will overwrite the
 * previous value. A rule is only automatically deleted when the client to
 * which it is attached is destroyed or when the extension which created it
 * is disabled.
 *
 * \a ch_route is as for xnice_vi_set_routing(): the bitwise OR of
 * #xnice_ch_route_bits, and is verified not to contain any unknown bits.
 * \a flags is currently unused and is verified to be 0.
 *
 * Returns zero on success, or a negative error value (-ENOSPC if no
 * ch_route-table entries are available).
 */
XNICE_HELPER(int, xnice_host_set_routing,
              (void *ctx, enum xnice_scope scope, unsigned ch_route,
               unsigned flags));

/** Returns true iff the caller is the administrative PF.
 *
 * May be used to restrict some plugin capabilities to privileged users only.
 *
 * This function cannot fail. */
__attribute__((const))
XNICE_HELPER(bool, xnice_is_admin, (void *ctx));

/** Delete every entry in the CAM and reset it to a freshly-initialised state.
 *
 * If the CAM is a DCAM then all entries are set to zero.
 *
 * Returns zero on success, or a negative error value */
XNICE_HELPER(int, xnice_cam_reset, (struct xnice_cam *cam));

/** Inserts a new value in the CAM.
 *
 * \a mask and \a priority are used for TCAM and STCAM types only. This
 * function will fail (-EEXIST) if a duplicate entry is already present.
 *
 * Returns zero on success, or a negative error value */
XNICE_HELPER(int, xnice_cam_insert, (struct xnice_cam *cam, const void *key,
                               const void *mask, unsigned priority,
                               const void *value));

/** Changes the value of an existing item in the CAM.
 *
 * \a mask is used for TCAM and STCAM types only. This function will fail
 * (-ENOENT) if the given key/mask is not already present.
 *
 * Returns zero on success, or a negative error value */
XNICE_HELPER(int, xnice_cam_update, (struct xnice_cam *cam, const void *key,
                               const void *mask, const void *value));

/** Removes an existing item from the CAM.
 *
 * \a mask is used for TCAM and STCAM types only. This function will fail
 * (-ENOENT) if the given key/mask is not found.
 *
 * Returns zero on success, or a negative error value */
XNICE_HELPER(int, xnice_cam_delete, (struct xnice_cam *cam, const void *key,
                               const void *mask));

/** Retrieves the value for a given key lookup, exactly as is performed in the
 * hardware.
 *
 * Returns zero on success, or a negative error value */
XNICE_HELPER(int, xnice_cam_lookup, (struct xnice_cam *cam, const void *key,
                               void *value));

/** Retrieves the value for a given key lookup where both the key and mask
 * must match.
 *
 * \a mask is used for TCAM and STCAM types only; for other types this
 * function is identical to xnice_cam_lookup().
 *
 * Returns zero on success, or a negative error value */
XNICE_HELPER(int, xnice_cam_get_by_key, (struct xnice_cam *cam, const void *key,
                                   const void *mask, void *value));

#endif  /* __bpf__ */
#endif
