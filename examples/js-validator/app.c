#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "time.h"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "onvif_media_signing_common.h"
#include "onvif_media_signing_validator.h"

static onvif_media_signing_t *g_oms_ctx = NULL;
static char *g_codec_name = "";

int oms_init_validation(int codec_type) {
    if (!g_oms_ctx) {
        g_oms_ctx = onvif_media_signing_create((MediaSigningCodec)codec_type);
        if (!g_oms_ctx) {
            printf("❌ Failed to create Media Signing context\n");
            return 0;
        }
        g_codec_name = codec_type == 0 ? "H.264" : (codec_type == 1 ? "H.265" : "Unsupported");
    }
    return 1;
}

int oms_add_cert(const uint8_t *cert, size_t cert_size) {
    if (!g_oms_ctx) {
        printf("No Media Signing session created\n");
        return 0;
    }
    // Add one certificate file.
    MediaSigningReturnCode rc = onvif_media_signing_set_trusted_certificate(
        g_oms_ctx, (const char*)cert, cert_size);
    if (rc != OMS_OK) {
        printf("❌ Failed to set trusted certificate (code %d)\n", rc);
        return 0;
    }
    printf("Successfully set trusted certificate of %zu bytes\n", cert_size);

    return 1;
}

int oms_validate_nalu(const uint8_t *unit, size_t unit_size, int codec_type) {
    if (!g_oms_ctx) {
        printf("No Media Signing session created\n");
        return 0;
    }

    // Feed one NALU (Unit). No need to collect reports during this stage.
    MediaSigningReturnCode rc = onvif_media_signing_add_nalu_and_authenticate(
        g_oms_ctx, unit, unit_size, NULL);
    if (rc != OMS_OK) {
        printf("❌ Failed to add NALU (code %d)\n", rc);
        return 0;
    }

    return 1;
}

int oms_get_final_verdict() {
    if (!g_oms_ctx) {
        printf("❌ No Media Signing session created.\n");
        return 0;
    }

    onvif_media_signing_authenticity_t *report = onvif_media_signing_get_authenticity_report(g_oms_ctx);
    if (!report) {
        printf("❌ No authenticity report available.\n");
        return 0;
    }

    // The validation result can be one of four:
    //   1) Valid (1), 2) Not valid (2), 3) Not signed (3), or 4) Unknown (0)
    int authenticity = 0; // Unknown

    if (report->accumulated_validation.authenticity_and_provenance == OMS_AUTHENTICITY_AND_PROVENANCE_OK ||
        report->accumulated_validation.authenticity_and_provenance == OMS_AUTHENTICITY_AND_PROVENANCE_OK_WITH_MISSING_INFO) {
        authenticity = 1;
    } else if (report->accumulated_validation.authenticity_and_provenance == OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK) {
        authenticity = 2;
    } else if (report->accumulated_validation.authenticity_and_provenance == OMS_AUTHENTICITY_AND_PROVENANCE_NOT_FEASIBLE) {
        authenticity = 3;
    }

    onvif_media_signing_authenticity_report_free(report);
    return authenticity;
}

void oms_free() {
    if (g_oms_ctx) {
        onvif_media_signing_free(g_oms_ctx);
        g_oms_ctx = NULL;
    }
}

void oms_reset() {
    if (g_oms_ctx) {
        onvif_media_signing_free(g_oms_ctx);
        g_oms_ctx = NULL;
    }
}

#define EPOCH_DIFF_US 11644473600000000LL  // Difference between 1601 and 1970 in microseconds
#define MICROSEC_TO_100NSEC 10LL  // 1 microsecond = 10 × 100-nanosecond intervals
// Convert 1601-based timestamp (100-nanosecond intervals since 1601) to Unix timestamp
// (microseconds)
int64_t
convert_1601_to_unix_us(int64_t timestamp)
{
  return (timestamp / MICROSEC_TO_100NSEC) - EPOCH_DIFF_US;
}

static char report[2048];
static char status[512];
static char summary[512];
static char interval[512];
static char product[512];
static char version[512];

char* oms_get_report_str(double file_duration) {
    memset(report, 0, sizeof(report));
    memset(status, 0, sizeof(status));
    memset(summary, 0, sizeof(summary));
    memset(interval, 0, sizeof(interval));
    memset(product, 0, sizeof(product));
    memset(version, 0, sizeof(version));

    if (!g_oms_ctx)
        return "No active session.";

    onvif_media_signing_authenticity_t *auth = onvif_media_signing_get_authenticity_report(g_oms_ctx);
    if (!auth)
        return "No authenticity report available.";

    onvif_media_signing_accumulated_validation_t *acc = &auth->accumulated_validation;
    const char *reason_str = "The authenticity status of the Public key and video content is unknown";
    // The validation result can be one of four:
    //   1) Valid (1), 2) Not valid (2), 3) Not signed (3), or 4) Unknown (0)
    // The last can happen if the file is not signed or if there is no SEI with a
    // signature.
    int authenticity = 0; // Unknown

    printf("OMS Report: authenticity_and_provenance = %d, provenance = %d, authenticity = %d\n", acc->authenticity_and_provenance, acc->provenance, acc->authenticity);
    // Determine verdict string
    switch (acc->authenticity_and_provenance) {
        case OMS_AUTHENTICITY_AND_PROVENANCE_OK:
            reason_str = "The Public key is trusted and the validated video content is correct.";
            authenticity = 1;
            break;
        case OMS_AUTHENTICITY_AND_PROVENANCE_OK_WITH_MISSING_INFO:
            reason_str = "The Public key is trusted, but there are missing frames among the validated video content. Note that the intention is unknown.";
            authenticity = 1;
            break;
        case OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK:
            if (acc->authenticity == OMS_AUTHENTICITY_OK) {
                reason_str = "The Public key could not be verified. Forgot to add a trusted CA certificate?";
            } else {
                reason_str = "The video content is not unaltered.";
            }
            authenticity = 2;
            break;
        case OMS_AUTHENTICITY_AND_PROVENANCE_NOT_FEASIBLE:
            reason_str = "The video authenticity cannot be determined.";
            authenticity = 3;
            break;
        default:
            break;
    }

    // Convert timestamps if available
    char first_str[64] = "N/A";
    char last_str[64] = "N/A";
    double validated_duration = 0.0;
    double dangling_end = 0.0;
    int64_t first_timestamp = convert_1601_to_unix_us(acc->first_timestamp);
    int64_t last_timestamp = convert_1601_to_unix_us(acc->last_timestamp);
    time_t ft = first_timestamp / 1000000;
    time_t lt = last_timestamp / 1000000;
    strftime(first_str, sizeof(first_str), "%a %Y-%m-%d %H:%M:%S GMT", gmtime(&ft));
    strftime(last_str, sizeof(last_str), "%a %Y-%m-%d %H:%M:%S GMT", gmtime(&lt));
    validated_duration = (double)(last_timestamp - first_timestamp) / 1000000;
    dangling_end = file_duration - validated_duration;

    if (authenticity == 1 || authenticity == 2) {
        if (authenticity == 2) {
            snprintf(status, sizeof(status),
                "Video authenticity: NOT VALID\n"
                "Reason: %s\n"
                "Codec: %s\n",
                reason_str,
                g_codec_name
            );
            snprintf(summary, sizeof(summary),
                "Received frames : %5u  [%6.2f sec]\n",
                acc->number_of_received_frames,
                file_duration
            );
        } else if (authenticity == 1) {
            snprintf(status, sizeof(status),
                "Video authenticity: VALID\n"
                "Reason: %s\n"
                "Codec: %s\n",
                reason_str,
                g_codec_name
            );
            snprintf(summary, sizeof(summary),
                "Received frames : %5u  [%6.2f sec]\n"
                "Validated frames: %5u  [%6.2f sec]\n"
                "Dangling end*   : %5u  [%6.2f sec]\n"
                "*frames at the end of a recording that can not be verified\n"
                " since these frames lack an associated signature.\n",
                acc->number_of_received_frames,
                file_duration,
                acc->number_of_validated_frames,
                validated_duration,
                acc->number_of_pending_frames,
                dangling_end
            );
        }
        snprintf(interval, sizeof(interval),
            "Start: %s\n"
            "End  : %s\n",
            first_str,
            last_str
        );
        snprintf(product, sizeof(product),
            "Manufacturer    : %s\n"
            "Serial Number   : %s\n"
            "Firmware Version: %s\n",
            auth->vendor_info.manufacturer,
            auth->vendor_info.serial_number,
            auth->vendor_info.firmware_version
        );
        snprintf(version, sizeof(version),
            "Validator: %s\n"
            "Device   : %s\n",
            onvif_media_signing_get_version(),
            auth->version_on_signing_side ? auth->version_on_signing_side : "N/A"
        );
        snprintf(report, sizeof(report),
            "AUTHENTICITY SUMMARY\n"
            "--------------------\n"
            "%s\n"
            "FRAME SUMMARY\n"
            "-------------\n"
            "%s\n"
            "VALIDATED RANGE\n"
            "---------------\n"
            "%s\n"
            "PRODUCT INFORMATION\n"
            "-------------------\n"
            "%s\n"
            "MEDIA SIGNING FRAMEWORK\n"
            "-----------------------\n"
            "%s",
            status,
            summary,
            interval,
            product,
            version
        );
    } else {
        snprintf(status, sizeof(status),
            "Video authenticity: %s\n"
            "Reason: %s\n"
            "Codec: %s\n",
            authenticity == 3 ? "NOT SIGNED" : "UNKOWN",
            reason_str,
            g_codec_name
        );
        snprintf(summary, sizeof(summary),
            "Received frames : %5u  [%6.2f sec]\n",
            acc ? acc->number_of_received_frames : 0,
            file_duration
        );
        snprintf(version, sizeof(version),
            "Validator: %s\n",
            onvif_media_signing_get_version()
        );
        snprintf(report, sizeof(report),
            "AUTHENTICITY SUMMARY\n"
            "--------------------\n"
            "%s\n"
            "FRAME SUMMARY\n"
            "-------------\n"
            "%s\n"
            "MEDIA SIGNING FRAMEWORK\n"
            "-----------------------\n"
            "%s",
            status,
            summary,
            version
        );
    }

    onvif_media_signing_authenticity_report_free(auth);
    return report;
}

// TODO: This mini report can be simplified a lot. Should not be necessary to parse text.
const char* oms_get_mini_report_str() {
    static char mini_report[512];
    memset(mini_report, 0, sizeof(mini_report));

    if (!g_oms_ctx)
        return "No active session.";

    onvif_media_signing_authenticity_t *auth = onvif_media_signing_get_authenticity_report(g_oms_ctx);
    if (!auth)
        return "No authenticity report available.";

    onvif_media_signing_accumulated_validation_t *acc = &auth->accumulated_validation;
    const char *verdict_str = "unknown";

    // The validation result can be one of four:
    //   1) Valid (1), 2) Not valid (2), 3) Not signed (3), or 4) Unknown (0)
    // The last can happen if the file is not signed or if there is no SEI with a
    // signature.
    int authenticity = 0; // Unknown

    if (acc->authenticity_and_provenance == OMS_AUTHENTICITY_AND_PROVENANCE_OK ||
        acc->authenticity_and_provenance == OMS_AUTHENTICITY_AND_PROVENANCE_OK_WITH_MISSING_INFO) {
        authenticity = 1;
    } else if (acc->authenticity_and_provenance == OMS_AUTHENTICITY_AND_PROVENANCE_NOT_OK) {
        authenticity = 2;
    } else if (acc->authenticity_and_provenance == OMS_AUTHENTICITY_AND_PROVENANCE_NOT_FEASIBLE) {
        authenticity = 3;
    }

    if (authenticity == 2) {
        verdict_str = "invalid";
    } else if (authenticity == 1) {
        verdict_str = "valid";
    } else if (authenticity == 3) {
        verdict_str = "unsigned";
    } else {
        verdict_str = "unknown";
    }

    // Convert timestamps if available (using the real field names from oms_get_report_str)
    char first_str[64] = "N/A";
    char last_str[64] = "N/A";
    int64_t first_timestamp = convert_1601_to_unix_us(acc->first_timestamp);
    int64_t last_timestamp = convert_1601_to_unix_us(acc->last_timestamp);
    time_t ft = first_timestamp / 1000000;
    time_t lt = last_timestamp / 1000000;
    strftime(first_str, sizeof(first_str), "%Y-%m-%d %H:%M:%S", gmtime(&ft));
    strftime(last_str, sizeof(last_str), "%Y-%m-%d %H:%M:%S", gmtime(&lt));

    // Create structured mini report
    snprintf(mini_report, sizeof(mini_report),
        "Verdict: %s\n"
        "First frame: %s\n"
        "Last validated frame: %s\n"
        "Validated frames: %u\n",
        verdict_str,
        first_str,
        last_str,
        acc->number_of_validated_frames
    );

    onvif_media_signing_authenticity_report_free(auth);
    return mini_report;
}

static char cert_info[4096];

const char* oms_print_cert(const uint8_t *pem_data, size_t pem_size) {
    memset(cert_info, 0, sizeof(cert_info));

    BIO *bio = BIO_new_mem_buf(pem_data, (int)pem_size);
    if (!bio) {
        snprintf(cert_info, sizeof(cert_info), "Failed to create BIO\n");
        return cert_info;
    }

    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!cert) {
        snprintf(cert_info, sizeof(cert_info), "Failed to parse certificate\n");
        return cert_info;
    }

    BIO *out = BIO_new(BIO_s_mem());
    if (!out) {
        X509_free(cert);
        snprintf(cert_info, sizeof(cert_info), "Failed to create output BIO\n");
        return cert_info;
    }

    X509_print_ex(out, cert, 0, 0);

    char *buf = NULL;
    long len = BIO_get_mem_data(out, &buf);
    if (len > 0 && buf) {
        size_t copy_len = (size_t)len < sizeof(cert_info) - 1 ? (size_t)len : sizeof(cert_info) - 1;
        memcpy(cert_info, buf, copy_len);
        cert_info[copy_len] = '\0';
    }

    BIO_free(out);
    X509_free(cert);
    return cert_info;
}

int main() {
    return 0;
}

const char* oms_print_cert_chain(void) {
    if (!g_oms_ctx)
        return "No active session.";

    static char *cert_chain_str = onvif_media_signing_get_certificate_chain(g_oms_ctx);
    return cert_chain_str;
}
