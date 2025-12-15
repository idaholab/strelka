from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t, int32_t
from posix.types cimport off_t
from posix.stat cimport struct_stat

cdef extern from "<xar/xar.h>":
    const char* XAR_VERSION

    struct xar_header:
        uint32_t magic
        uint16_t size
        uint16_t version
        uint64_t toc_length_compressed
        uint64_t toc_length_uncompressed
        uint32_t cksum_alg

    ctypedef xar_header xar_header_t

    const uint32_t XAR_HEADER_MAGIC
    const char* XAR_EA_FORK

    const uint32_t XAR_CKSUM_NONE
    const uint32_t XAR_CKSUM_SHA1
    const uint32_t XAR_CKSUM_MD5
    const uint32_t XAR_CKSUM_SHA256
    const uint32_t XAR_CKSUM_SHA512

    ctypedef void* xar_errctx_t
    ctypedef const void *xar_file_t;
    ctypedef const void *xar_iter_t;
    ctypedef const void *xar_t;
    ctypedef const void *xar_subdoc_t;
    ctypedef const void *xar_signature_t;

    ctypedef struct xar_stream:
        char *next_out
        unsigned int avail_out
        unsigned long long total_in
        unsigned long long total_out
        void *state

    ctypedef int32_t (*err_handler)(int32_t, int32_t, xar_errctx_t, void*)
    ctypedef int32_t (*xar_signer_callback)(xar_signature_t, void*, uint8_t*, uint32_t, uint8_t**, uint32_t*)
    ctypedef void (*xar_progress_callback)(xar_t, xar_file_t, size_t)

    const int32_t READ
    const int32_t WRITE

    const int32_t XAR_STREAM_OK
    const int32_t XAR_STREAM_END
    const int32_t XAR_STREAM_ERR

    const char* XAR_OPT_OWNERSHIP
    const char* XAR_OPT_VAL_SYMBOLIC
    const char* XAR_OPT_VAL_NUMERIC
    const char* XAR_OPT_TOCCKSUM
    const char* XAR_OPT_FILECKSUM
    const char* XAR_OPT_VAL_NONE
    const char* XAR_OPT_VAL_SHA1
    const char* XAR_OPT_VAL_SHA256
    const char* XAR_OPT_VAL_SHA512
    const char* XAR_OPT_VAL_MD5
    const char* XAR_OPT_COMPRESSION
    const char* XAR_OPT_COMPRESSIONARG
    const char* XAR_OPT_VAL_GZIP
    const char* XAR_OPT_VAL_BZIP
    const char* XAR_OPT_VAL_LZMA
    const char* XAR_OPT_RSIZE
    const char* XAR_OPT_COALESCE
    const char* XAR_OPT_LINKSAME
    const char* XAR_OPT_PROPINCLUDE
    const char* XAR_OPT_PROPEXCLUDE
    const char* XAR_OPT_SAVESUID
    const char* XAR_OPT_VAL_TRUE
    const char* XAR_OPT_VAL_FALSE

    const uint32_t XAR_SIG_SHA1RSA

    const uint32_t XAR_SEVERITY_DEBUG
    const uint32_t XAR_SEVERITY_INFO
    const uint32_t XAR_SEVERITY_NORMAL
    const uint32_t XAR_SEVERITY_WARNING
    const uint32_t XAR_SEVERITY_NONFATAL
    const uint32_t XAR_SEVERITY_FATAL

    const uint32_t XAR_ERR_ARCHIVE_CREATION
    const uint32_t XAR_ERR_ARCHIVE_EXTRACTION

    xar_t xar_open(const char*, int32_t)
    xar_t xar_open_digest_verify(const char*, int32_t, void*, size_t)
    int xar_close(xar_t)

    xar_header_t xar_header_get(xar_t)

    xar_file_t xar_add(xar_t, const char*)
    xar_file_t xar_add_frombuffer(xar_t, xar_file_t, const char*, char*, size_t)
    xar_file_t xar_add_folder(xar_t, xar_file_t, const char*, struct_stat*)
    xar_file_t xar_add_frompath(xar_t, xar_file_t, const char*, const char*)
    xar_file_t xar_add_from_archive(xar_t, xar_file_t, const char*, xar_t, xar_file_t)

    int32_t xar_extract(xar_t, xar_file_t)
    int32_t xar_extract_tofile(xar_t, xar_file_t, const char*)
    int32_t xar_extract_tobuffer(xar_t, xar_file_t, char**)
    int32_t xar_extract_tobuffersz(xar_t, xar_file_t, char**, size_t*)
    int32_t xar_extract_tostream_init(xar_t, xar_file_t, xar_stream*)
    int32_t xar_extract_tostream(xar_stream*)
    int32_t xar_extract_tostream_end(xar_stream*)

    int32_t xar_verify(xar_t, xar_file_t)
    int32_t xar_verify_progress(xar_t, xar_file_t, xar_progress_callback)
    void* xar_get_toc_checksum(xar_t, size_t*)
    int32_t xar_get_toc_checksum_type(xar_t)

    const char* xar_opt_get(xar_t, const char*)
    int32_t xar_opt_set(xar_t, const char*, const char*)
    int32_t xar_opt_unset(xar_t, const char*)

    int32_t xar_prop_set(xar_file_t, const char*, const char*)
    int32_t xar_prop_create(xar_file_t, const char*, const char*)
    int32_t xar_prop_get(xar_file_t, const char*, const char**)

    xar_iter_t xar_iter_new()
    void xar_iter_free(xar_iter_t)

    const char* xar_prop_first(xar_file_t, xar_iter_t)
    const char* xar_prop_next(xar_iter_t)

    void xar_prop_unset(xar_file_t, const char*)
    xar_file_t xar_file_first(xar_t, xar_iter_t)
    xar_file_t xar_file_next(xar_iter_t)

    const char* xar_attr_get(xar_file_t, const char*, const char*)
    int32_t xar_attr_set(xar_file_t, const char*, const char*, const char*)
    const char* xar_attr_first(xar_file_t, const char*, xar_iter_t)
    const char* xar_attr_next(xar_iter_t)

    xar_subdoc_t xar_subdoc_new(xar_t, const char*)
    int32_t xar_subdoc_prop_set(xar_subdoc_t, const char*, const char*)
    int32_t xar_subdoc_prop_get(xar_subdoc_t, const char*, const char**)
    int32_t xar_subdoc_attr_set(xar_subdoc_t, const char*, const char*, const char*)
    const char *xar_subdoc_attr_get(xar_subdoc_t, const char*, const char*)
    xar_subdoc_t xar_subdoc_first(xar_t)
    xar_subdoc_t xar_subdoc_next(xar_subdoc_t)
    const char *xar_subdoc_name(xar_subdoc_t)
    int32_t xar_subdoc_copyout(xar_subdoc_t, unsigned char**, unsigned int*)
    int32_t xar_subdoc_copyin(xar_subdoc_t, const unsigned char*, unsigned int)
    void xar_subdoc_remove(xar_subdoc_t)

    xar_signature_t xar_signature_new(xar_t, const char*, int32_t, xar_signer_callback, void*)
    xar_signature_t xar_signature_new_extended(xar_t, const char*, int32_t, xar_signer_callback, void*)
    const char* xar_signature_type(xar_signature_t)
    xar_signature_t xar_signature_first(xar_t)
    xar_signature_t xar_signature_next(xar_signature_t)
    int32_t xar_signature_add_x509certificate(xar_signature_t, const uint8_t*, uint32_t)
    int32_t xar_signature_get_x509certificate_count(xar_signature_t)
    int32_t xar_signature_get_x509certificate_data(xar_signature_t, int32_t, const uint8_t**, uint32_t*)
    uint8_t xar_signature_copy_signed_data(xar_signature_t, uint8_t**, uint32_t*, uint8_t**, uint32_t*, off_t*)

    char* xar_get_size(xar_t, xar_file_t)
    char* xar_get_type(xar_t, xar_file_t)
    char* xar_get_mode(xar_t, xar_file_t)
    char* xar_get_owner(xar_t, xar_file_t)
    char* xar_get_group(xar_t, xar_file_t)
    char* xar_get_mtime(xar_t, xar_file_t)

    int xar_path_issane(char*)

    void xar_register_errhandler(xar_t, err_handler, void*)
    xar_t xar_err_get_archive(xar_errctx_t)
    xar_file_t xar_err_get_file(xar_errctx_t)
    const char* xar_err_get_string(xar_errctx_t)
    int xar_err_get_errno(xar_errctx_t)
    void xar_err_set_file(xar_t, xar_file_t)
    void xar_err_set_formatted_string(xar_t, const char*, ...)
    void xar_err_set_string(xar_t, const char*)
    void xar_err_set_errno(xar_t, int)
    void xar_err_new(xar_t)
    int32_t xar_err_callback(xar_t, int32_t, int32_t)

    void xar_serialize(xar_t, const char*)
    char* xar_get_path(xar_file_t)
    off_t xar_get_heap_offset(xar_t)
    uint64_t xar_ntoh64(uint64_t)

