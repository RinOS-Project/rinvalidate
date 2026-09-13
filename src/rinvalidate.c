/* SPDX-License-Identifier: Apache-2.0 */
/* Standalone software validator for canonical RinOS v3 RIN/NDRV images. */
#include "rin_formats_v3.h"

#include <errno.h>
#include <limits.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RDS1_MAGIC UINT32_C(0x31534452)
#define RDS1_HEADER_SIZE 48u
#define RIN_MAX_SECTIONS 32u
#define RIN_MAX_DEPENDENCIES 64u
#define RIN_MAX_IMAGE_SIZE (UINT64_C(512) * 1024u * 1024u)
#define RIN_MAX_IMPORTS 4096u
#define RIN_MAX_EXPORTS 4096u
#define RIN_X86_USER_LIMIT UINT64_C(0xc0000000)
#define DRIVER_MAX_MATCHES 64u
#define DRIVER_MAX_IMAGE_SIZE (UINT64_C(128) * 1024u * 1024u)

typedef struct Options {
    const char *kind;
    const char *arch;
    const char *trust_key;
    const char *image_path;
    int allow_unsigned;
    int exact_dependencies;
    int exact_exports;
    int exact_imports;
    const char *required_dependencies[64];
    size_t required_dependency_count;
    const char *required_exports[128];
    size_t required_export_count;
    const char *required_imports[128];
    size_t required_import_count;
} Options;

typedef struct Blob {
    uint8_t *data;
    size_t size;
} Blob;

static void usage(FILE *stream) {
    fprintf(stream,
        "usage: rinvalidate --kind executable|service|library|driver [options] IMAGE\n"
        "options: --arch x86|x86_64 --trust-key KEY.der --allow-unsigned\n"
        "         --exact-dependencies --require-dependency NAME\n"
        "         --exact-exports --require-export NAME@function|data\n"
        "         --exact-imports --require-import LIBRARY:NAME@function|data\n");
}

static int read_file(const char *path, Blob *blob) {
    FILE *file = fopen(path, "rb");
    long length;
    if (!file) {
        fprintf(stderr, "rinvalidate: cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) < 0 ||
        fseek(file, 0, SEEK_SET) != 0 || (unsigned long long)length > SIZE_MAX) {
        fprintf(stderr, "rinvalidate: cannot determine size of %s\n", path);
        fclose(file);
        return -1;
    }
    blob->size = (size_t)length;
    blob->data = (uint8_t *)malloc(blob->size ? blob->size : 1u);
    if (!blob->data || (blob->size && fread(blob->data, 1, blob->size, file) != blob->size)) {
        fprintf(stderr, "rinvalidate: cannot read %s\n", path);
        free(blob->data);
        blob->data = NULL;
        fclose(file);
        return -1;
    }
    fclose(file);
    return 0;
}

static int range_u64(uint64_t offset, uint64_t length, uint64_t limit) {
    return offset <= limit && length <= limit - offset;
}

static int overlap_u64(uint64_t a, uint64_t as, uint64_t b, uint64_t bs) {
    return as != 0 && bs != 0 && a < b + bs && b < a + as;
}

static int power_of_two(uint32_t value) {
    return value != 0 && (value & (value - 1u)) == 0;
}

static int zero_bytes(const uint8_t *data, size_t size) {
    size_t i;
    for (i = 0; i < size; ++i)
        if (data[i] != 0) return 0;
    return 1;
}

static const char *string_at(const char *table, uint64_t table_size, uint32_t offset) {
    uint64_t i;
    if (offset >= table_size) return NULL;
    for (i = offset; i < table_size; ++i)
        if (table[i] == '\0') return table + offset;
    return NULL;
}

static int arch_matches(uint16_t actual, const char *expected) {
    if (!expected) return actual == RIN_ARCH_X86 || actual == RIN_ARCH_X86_64;
    if (strcmp(expected, "x86") == 0 || strcmp(expected, "i686") == 0)
        return actual == RIN_ARCH_X86;
    if (strcmp(expected, "x86_64") == 0 || strcmp(expected, "amd64") == 0)
        return actual == RIN_ARCH_X86_64;
    return 0;
}

static int section_contains(const RinSectionV3 *section, uint64_t address, uint64_t size) {
    return address >= section->virtual_address &&
           address - section->virtual_address <= section->memory_size &&
           size <= section->memory_size - (address - section->virtual_address);
}

static int verify_signature(const uint8_t *image, size_t image_size,
                            uint64_t signature_offset, uint32_t signature_size,
                            uint16_t signature_algorithm, uint16_t hash_algorithm,
                            const uint8_t content_hash[32], uint32_t flags,
                            const char *trust_key, int allow_unsigned) {
    Blob key = {0};
    uint8_t calculated[SHA256_DIGEST_LENGTH];
    uint8_t signed_digest[SHA256_DIGEST_LENGTH];
    uint8_t key_id[SHA256_DIGEST_LENGTH];
    RSA *rsa = NULL;
    const uint8_t *cursor;
    uint16_t envelope_signature_size;
    int signed_flag = flags != 0;
    int result = -1;

    if (!signed_flag) {
        if (!allow_unsigned || signature_offset != 0 || signature_size != 0 ||
            signature_algorithm != 0 || hash_algorithm != 0 ||
            !zero_bytes(content_hash, 32)) {
            fprintf(stderr, "rinvalidate: image is unsigned; a trusted key is required\n");
            goto done;
        }
        result = 0;
        goto done;
    }
    if (!trust_key || signature_algorithm != RIN_IMAGE_SIGNATURE_RSA_PKCS1_SHA256 ||
        hash_algorithm != RIN_IMAGE_HASH_SHA256 || signature_offset < 256u ||
        signature_size < RDS1_HEADER_SIZE || signature_offset > image_size ||
        signature_size > image_size - signature_offset ||
        signature_offset + signature_size != image_size ||
        signature_size - RDS1_HEADER_SIZE > UINT16_MAX) {
        fprintf(stderr, "rinvalidate: malformed signature envelope\n");
        goto done;
    }
    SHA256(image + 256u, (size_t)signature_offset - 256u, calculated);
    if (memcmp(calculated, content_hash, sizeof(calculated)) != 0) {
        fprintf(stderr, "rinvalidate: content hash mismatch\n");
        goto done;
    }
    if (read_file(trust_key, &key) != 0 || key.size == 0) goto done;
    SHA256(key.data, key.size, key_id);
    cursor = image + signature_offset;
    envelope_signature_size = (uint16_t)cursor[10] |
                              ((uint16_t)cursor[11] << 8);
    if (signature_size < RDS1_HEADER_SIZE ||
        ((const uint32_t *)cursor)[0] != RDS1_MAGIC ||
        cursor[4] != 1 || cursor[5] != 0 || cursor[6] != RDS1_HEADER_SIZE || cursor[7] != 0 ||
        cursor[8] != RIN_IMAGE_SIGNATURE_RSA_PKCS1_SHA256 ||
        envelope_signature_size != signature_size - RDS1_HEADER_SIZE ||
        memcmp(cursor + 12, key_id, sizeof(key_id)) != 0 ||
        !zero_bytes(cursor + 44, 4)) {
        fprintf(stderr, "rinvalidate: signature envelope identity or fields are invalid\n");
        goto done;
    }
    cursor = key.data;
    rsa = d2i_RSAPublicKey(NULL, &cursor, (long)key.size);
    SHA256(image, (size_t)signature_offset, signed_digest);
    if (!rsa || cursor != key.data + key.size ||
        RSA_verify(NID_sha256, signed_digest, sizeof(signed_digest),
                   image + signature_offset + RDS1_HEADER_SIZE,
                   (unsigned int)(signature_size - RDS1_HEADER_SIZE), rsa) != 1) {
        fprintf(stderr, "rinvalidate: RSA signature rejected\n");
        goto done;
    }
    result = 0;
done:
    RSA_free(rsa);
    free(key.data);
    return result;
}

static int validate_strings_and_tables(const uint8_t *image,
                                       const RinHeaderV3 *header,
                                       const RinSectionV3 **sections,
                                       const RinDependencyV3 **dependencies,
                                       const char **strings,
                                       uint64_t content_limit) {
    uint64_t section_bytes, dependency_bytes;
    if (header->section_count == 0 || header->section_count > RIN_MAX_SECTIONS ||
        header->dependency_count > RIN_MAX_DEPENDENCIES || header->image_size == 0 ||
        header->image_size > RIN_MAX_IMAGE_SIZE || header->reserved0 != 0 ||
        !zero_bytes((const uint8_t *)header->reserved, sizeof(header->reserved)))
        return -1;
    section_bytes = (uint64_t)header->section_count * sizeof(RinSectionV3);
    dependency_bytes = (uint64_t)header->dependency_count * sizeof(RinDependencyV3);
    if (header->section_table_offset < sizeof(RinHeaderV3) ||
        !range_u64(header->section_table_offset, section_bytes, content_limit) ||
        (header->dependency_count && header->dependency_table_offset < sizeof(RinHeaderV3)) ||
        !range_u64(header->dependency_table_offset, dependency_bytes, content_limit) ||
        header->string_table_offset < sizeof(RinHeaderV3) || header->string_table_size == 0 ||
        !range_u64(header->string_table_offset, header->string_table_size, content_limit) ||
        overlap_u64(header->section_table_offset, section_bytes,
                    header->dependency_table_offset, dependency_bytes) ||
        overlap_u64(header->section_table_offset, section_bytes,
                    header->string_table_offset, header->string_table_size) ||
        overlap_u64(header->dependency_table_offset, dependency_bytes,
                    header->string_table_offset, header->string_table_size))
        return -1;
    *sections = (const RinSectionV3 *)(image + header->section_table_offset);
    *dependencies = (const RinDependencyV3 *)(image + header->dependency_table_offset);
    *strings = (const char *)(image + header->string_table_offset);
    if ((*strings)[0] != '\0') return -1;
    return 0;
}

static int symbol_matches(const char *actual, const char *requirement) {
    const char *at = strrchr(requirement, '@');
    size_t name_size = at ? (size_t)(at - requirement) : strlen(requirement);
    return strlen(actual) == name_size && memcmp(actual, requirement, name_size) == 0;
}

static int validate_rin(const Blob *blob, const Options *options) {
    const RinHeaderV3 *header;
    const RinSectionV3 *sections;
    const RinDependencyV3 *dependencies;
    const char *strings;
    const RinSectionV3 *code_section = NULL;
    const RinSectionV3 *relocations = NULL, *imports = NULL, *exports = NULL;
    unsigned int code_count = 0, reloc_count = 0, import_count = 0, export_count = 0;
    unsigned int tls_count = 0;
    unsigned int tls_relocation_count = 0;
    uint64_t content_limit;
    size_t i, j;
    if (blob->size < sizeof(RinHeaderV3)) return -1;
    header = (const RinHeaderV3 *)blob->data;
    if (header->magic != RIN_IMAGE_MAGIC || header->version != RIN_IMAGE_VERSION_3 ||
        header->header_size != sizeof(RinHeaderV3) || !arch_matches(header->architecture, options->arch) ||
        header->abi_major != RIN_IMAGE_ABI_MAJOR || header->abi_minor > RIN_IMAGE_ABI_MINOR ||
        (header->architecture == RIN_ARCH_X86 && header->abi_minor < RIN_IMAGE_ABI_MINOR_SPECIAL_SECTIONS)) {
        fprintf(stderr, "rinvalidate: RIN header is not current v3\n");
        return -1;
    }
    if ((header->flags & ~(RIN_IMAGE_EXECUTABLE | RIN_IMAGE_LIBRARY | RIN_IMAGE_GUI |
                           RIN_IMAGE_SERVICE | RIN_IMAGE_RELOCATABLE | RIN_IMAGE_ASLR |
                           RIN_IMAGE_SIGNED | RIN_IMAGE_USES_TLS)) != 0 ||
        ((header->flags & RIN_IMAGE_EXECUTABLE) != 0) == ((header->flags & RIN_IMAGE_LIBRARY) != 0) ||
        (strcmp(options->kind, "library") == 0 &&
         ((header->flags & RIN_IMAGE_LIBRARY) == 0 || (header->flags & (RIN_IMAGE_GUI | RIN_IMAGE_SERVICE)) != 0)) ||
        (strcmp(options->kind, "service") == 0 &&
         ((header->flags & (RIN_IMAGE_EXECUTABLE | RIN_IMAGE_SERVICE)) !=
          (RIN_IMAGE_EXECUTABLE | RIN_IMAGE_SERVICE))) ||
        (strcmp(options->kind, "executable") == 0 && (header->flags & RIN_IMAGE_EXECUTABLE) == 0) ||
        ((header->flags & RIN_IMAGE_ASLR) && !(header->flags & RIN_IMAGE_RELOCATABLE)) ||
        (header->architecture == RIN_ARCH_X86 &&
         (header->image_size >= RIN_X86_USER_LIMIT || header->preferred_base >= RIN_X86_USER_LIMIT ||
          header->preferred_base > UINT64_MAX - header->image_size ||
          header->preferred_base + header->image_size > RIN_X86_USER_LIMIT || header->entry_rva > UINT32_MAX))) {
        fprintf(stderr, "rinvalidate: RIN flags or address limits are invalid\n");
        return -1;
    }
    content_limit = (header->flags & RIN_IMAGE_SIGNED) ? header->signature_offset : blob->size;
    if ((header->flags & RIN_IMAGE_SIGNED) != 0 &&
        (!range_u64(header->signature_offset, header->signature_size, blob->size) ||
         header->signature_offset + header->signature_size != blob->size) ||
        ((header->flags & RIN_IMAGE_SIGNED) == 0 &&
         (header->signature_offset != 0 || header->signature_size != 0)) ||
        validate_strings_and_tables(blob->data, header, &sections, &dependencies, &strings,
                                    (header->flags & RIN_IMAGE_SIGNED) ? header->signature_offset : blob->size) != 0 ||
        verify_signature(blob->data, blob->size, header->signature_offset, header->signature_size,
                         header->signature_algorithm, header->hash_algorithm, header->content_hash,
                         (header->flags & RIN_IMAGE_SIGNED) != 0, options->trust_key, options->allow_unsigned) != 0) {
        fprintf(stderr, "rinvalidate: RIN top-level layout or signature is invalid\n");
        return -1;
    }
    for (i = 0; i < header->dependency_count; ++i) {
        if (!string_at(strings, header->string_table_size, dependencies[i].name_offset) ||
            (dependencies[i].flags & ~(RIN_DEPENDENCY_OPTIONAL | RIN_DEPENDENCY_PIN_IDENTITY)) != 0 ||
            dependencies[i].reserved != 0) {
            fprintf(stderr, "rinvalidate: invalid dependency table\n");
            return -1;
        }
    }
    for (i = 0; i < header->section_count; ++i) {
        const RinSectionV3 *section = &sections[i];
        int loadable = section->type >= RIN_IMAGE_SECTION_CODE && section->type <= RIN_IMAGE_SECTION_BSS;
        int alias = section->type >= RIN_IMAGE_SECTION_TLS && section->type <= RIN_IMAGE_SECTION_FINI_ARRAY;
        if (section->type == RIN_IMAGE_SECTION_INVALID || section->type > RIN_IMAGE_SECTION_FINI_ARRAY ||
            (section->type > RIN_IMAGE_SECTION_TLS && header->abi_minor < RIN_IMAGE_ABI_MINOR_SPECIAL_SECTIONS) ||
            (section->flags & ~(RIN_IMAGE_SECTION_READ | RIN_IMAGE_SECTION_WRITE |
                                RIN_IMAGE_SECTION_EXECUTE | RIN_IMAGE_SECTION_DISCARDABLE)) != 0 ||
            section->reserved != 0 || !power_of_two(section->alignment) || section->alignment > 0x200000u ||
            (section->virtual_address & (section->alignment - 1u)) != 0 ||
            !string_at(strings, header->string_table_size, section->name_offset)) {
            fprintf(stderr, "rinvalidate: invalid section metadata\n");
            return -1;
        }
        if (section->file_size && (section->file_offset < sizeof(RinHeaderV3) ||
            !range_u64(section->file_offset, section->file_size, content_limit))) {
            fprintf(stderr, "rinvalidate: section exceeds signed content\n");
            return -1;
        }
        if (loadable) {
            if (!section->memory_size || section->file_size > section->memory_size ||
                !range_u64(section->virtual_address, section->memory_size, header->image_size) ||
                ((section->flags & RIN_IMAGE_SECTION_WRITE) && (section->flags & RIN_IMAGE_SECTION_EXECUTE))) {
                fprintf(stderr, "rinvalidate: invalid loadable section range\n");
                return -1;
            }
            if (section->type == RIN_IMAGE_SECTION_CODE) {
                ++code_count;
                code_section = section;
                if (section->flags != (RIN_IMAGE_SECTION_READ | RIN_IMAGE_SECTION_EXECUTE) || !section->file_size)
                    return -1;
            } else if (section->type == RIN_IMAGE_SECTION_DATA || section->type == RIN_IMAGE_SECTION_BSS) {
                if (section->flags != (RIN_IMAGE_SECTION_READ | RIN_IMAGE_SECTION_WRITE)) return -1;
                if (section->type == RIN_IMAGE_SECTION_BSS && (section->file_size || section->file_offset)) return -1;
            } else if (section->flags != RIN_IMAGE_SECTION_READ) return -1;
        } else if (section->type == RIN_IMAGE_SECTION_RELOCATIONS || section->type == RIN_IMAGE_SECTION_IMPORTS ||
                   section->type == RIN_IMAGE_SECTION_EXPORTS) {
            if (!section->file_size || section->memory_size || section->file_offset < sizeof(RinHeaderV3) ||
                section->flags != RIN_IMAGE_SECTION_DISCARDABLE) return -1;
            if (section->type == RIN_IMAGE_SECTION_RELOCATIONS) { ++reloc_count; relocations = section; }
            if (section->type == RIN_IMAGE_SECTION_IMPORTS) { ++import_count; imports = section; if (section->file_size % sizeof(RinImportV3) || section->file_size / sizeof(RinImportV3) > RIN_MAX_IMPORTS) return -1; }
            if (section->type == RIN_IMAGE_SECTION_EXPORTS) { ++export_count; exports = section; if (section->file_size % sizeof(RinExportV3) || section->file_size / sizeof(RinExportV3) > RIN_MAX_EXPORTS) return -1; }
        } else if (section->type == RIN_IMAGE_SECTION_TLS) {
            ++tls_count;
            if (!section->memory_size || section->file_size > section->memory_size || section->flags != RIN_IMAGE_SECTION_READ) return -1;
        } else if (section->type == RIN_IMAGE_SECTION_UNWIND || section->type == RIN_IMAGE_SECTION_INIT_ARRAY || section->type == RIN_IMAGE_SECTION_FINI_ARRAY) {
            if (!section->memory_size || section->file_size != section->memory_size ||
                !range_u64(section->virtual_address, section->memory_size, header->image_size) || section->flags != RIN_IMAGE_SECTION_READ) return -1;
        } else if (section->type == RIN_IMAGE_SECTION_RESOURCES) {
            if (!section->file_size || section->memory_size || section->alignment < 8 || section->flags != RIN_IMAGE_SECTION_READ) return -1;
        }
        if (!alias && section->file_size &&
            (overlap_u64(section->file_offset, section->file_size, header->section_table_offset, (uint64_t)header->section_count * sizeof(RinSectionV3)) ||
             overlap_u64(section->file_offset, section->file_size, header->dependency_table_offset, (uint64_t)header->dependency_count * sizeof(RinDependencyV3)) ||
             overlap_u64(section->file_offset, section->file_size, header->string_table_offset, header->string_table_size))) return -1;
        for (j = 0; j < i; ++j) {
            const RinSectionV3 *other = &sections[j];
            if (!alias && !((other->type >= RIN_IMAGE_SECTION_TLS) && (other->type <= RIN_IMAGE_SECTION_FINI_ARRAY)) &&
                overlap_u64(section->file_offset, section->file_size, other->file_offset, other->file_size)) return -1;
            if (loadable && other->type >= RIN_IMAGE_SECTION_CODE && other->type <= RIN_IMAGE_SECTION_BSS &&
                overlap_u64(section->virtual_address, section->memory_size, other->virtual_address, other->memory_size)) return -1;
        }
    }
    if (code_count != 1 || reloc_count > 1 || import_count > 1 || export_count > 1 || tls_count > 1 ||
        (strcmp(options->kind, "library") == 0 && header->entry_rva != 0) ||
        (strcmp(options->kind, "library") != 0 &&
         (!code_section || !section_contains(code_section, header->entry_rva, 1)))) return -1;
    if (((header->flags & RIN_IMAGE_USES_TLS) != 0) != (tls_count == 1)) return -1;
    if (relocations) {
        const RinRelocationV3 *table = (const RinRelocationV3 *)(blob->data + relocations->file_offset);
        uint64_t count = relocations->file_size / sizeof(*table);
        for (i = 0; i < count; ++i) {
            uint64_t width = table[i].type == RIN_IMAGE_RELOCATION_ABS64 ? 8u : 4u;
            if (table[i].reserved0 || table[i].reserved1 || !table[i].virtual_address ||
                (i && table[i].virtual_address <= table[i - 1].virtual_address) ||
                (table[i].type != RIN_IMAGE_RELOCATION_ABS64 && table[i].type != RIN_IMAGE_RELOCATION_ABS32U &&
                 table[i].type != RIN_IMAGE_RELOCATION_ABS32S &&
                 !(table[i].type == RIN_IMAGE_RELOCATION_TLSOFF32S &&
                   header->abi_minor >= RIN_IMAGE_ABI_MINOR_TLSOFF32S) &&
                 !(header->abi_minor == 0 && table[i].type == RIN_IMAGE_RELOCATION_ABS32)) ||
                (header->architecture == RIN_ARCH_X86 && width != 4) ||
                !range_u64(table[i].virtual_address, width, header->image_size)) return -1;
            if (table[i].type == RIN_IMAGE_RELOCATION_TLSOFF32S)
                ++tls_relocation_count;
        }
        if (tls_relocation_count != 0 && tls_count != 1) return -1;
    }
    if (imports) {
        const RinImportV3 *table = (const RinImportV3 *)(blob->data + imports->file_offset);
        uint64_t count = imports->file_size / sizeof(*table);
        for (i = 0; i < count; ++i) {
            if (!string_at(strings, header->string_table_size, table[i].name_offset) || table[i].dependency_index >= header->dependency_count ||
                (table[i].kind != RIN_SYMBOL_FUNCTION &&
                 table[i].kind != RIN_SYMBOL_DATA) ||
                table[i].reserved0 || table[i].reserved1 ||
                !range_u64(table[i].target_rva, header->architecture == RIN_ARCH_X86 ? 4 : 8, header->image_size)) return -1;
        }
    }
    if (exports) {
        const RinExportV3 *table = (const RinExportV3 *)(blob->data + exports->file_offset);
        uint64_t count = exports->file_size / sizeof(*table);
        for (i = 0; i < count; ++i) {
            if (!string_at(strings, header->string_table_size, table[i].name_offset) ||
                (table[i].kind != RIN_SYMBOL_FUNCTION &&
                 table[i].kind != RIN_SYMBOL_DATA) ||
                table[i].reserved ||
                !range_u64(table[i].virtual_address, table[i].size ? table[i].size : 1, header->image_size)) return -1;
        }
    }
    if (options->exact_dependencies && header->dependency_count != options->required_dependency_count) return -1;
    for (i = 0; i < options->required_dependency_count; ++i) {
        int found = 0;
        for (j = 0; j < header->dependency_count; ++j)
            if (strcmp(string_at(strings, header->string_table_size, dependencies[j].name_offset), options->required_dependencies[i]) == 0) found = 1;
        if (!found) return -1;
    }
    if (options->exact_exports && (!exports || exports->file_size / sizeof(RinExportV3) != options->required_export_count)) return -1;
    for (i = 0; i < options->required_export_count; ++i) {
        int found = 0;
        if (exports) {
            const RinExportV3 *table = (const RinExportV3 *)(blob->data + exports->file_offset);
            for (j = 0; j < exports->file_size / sizeof(RinExportV3); ++j)
                if (symbol_matches(string_at(strings, header->string_table_size, table[j].name_offset), options->required_exports[i])) found = 1;
        }
        if (!found) return -1;
    }
    if (options->exact_imports && (!imports || imports->file_size / sizeof(RinImportV3) != options->required_import_count)) return -1;
    for (i = 0; i < options->required_import_count; ++i) {
        int found = 0;
        const char *colon = strchr(options->required_imports[i], ':');
        if (imports && colon) {
            char library[256];
            size_t library_size = (size_t)(colon - options->required_imports[i]);
            if (library_size < sizeof(library)) {
                memcpy(library, options->required_imports[i], library_size); library[library_size] = '\0';
                const RinImportV3 *table = (const RinImportV3 *)(blob->data + imports->file_offset);
                for (j = 0; j < imports->file_size / sizeof(RinImportV3); ++j) {
                    if (table[j].dependency_index < header->dependency_count &&
                        strcmp(string_at(strings, header->string_table_size, dependencies[table[j].dependency_index].name_offset), library) == 0 &&
                        symbol_matches(string_at(strings, header->string_table_size, table[j].name_offset), colon + 1)) found = 1;
                }
            }
        }
        if (!found) return -1;
    }
    return 0;
}

static int validate_driver(const Blob *blob, const Options *options) {
    const RinDriverHeaderV3 *header;
    const RinSectionV3 *sections;
    const RinSectionV3 *code_section = NULL;
    const RinSectionV3 *relocations = NULL;
    const char *strings;
    const RinDriverMatchV3 *matches;
    unsigned int code_count = 0;
    uint64_t content_limit;
    size_t i;
    if (blob->size < sizeof(RinDriverHeaderV3)) return -1;
    header = (const RinDriverHeaderV3 *)blob->data;
    if (header->magic != RIN_DRIVER_IMAGE_MAGIC || header->version != RIN_DRIVER_IMAGE_VERSION_3 ||
        header->header_size != sizeof(RinDriverHeaderV3) || !arch_matches(header->architecture, options->arch) ||
        header->abi_major != RIN_DRIVER_ABI_MAJOR || header->abi_minor != RIN_DRIVER_ABI_MINOR ||
        header->section_count == 0 || header->section_count > RIN_MAX_SECTIONS || header->match_count == 0 ||
        header->match_count > DRIVER_MAX_MATCHES || header->image_size == 0 || header->image_size > DRIVER_MAX_IMAGE_SIZE ||
        (header->architecture == RIN_ARCH_X86 && header->image_size >= RIN_X86_USER_LIMIT)) return -1;
    content_limit = (header->flags & RIN_DRIVER_IMAGE_SIGNED) ? header->signature_offset : blob->size;
    if ((header->flags & ~(RIN_DRIVER_IMAGE_SIGNED | RIN_DRIVER_IMAGE_RELOCATABLE | RIN_DRIVER_IMAGE_USES_MSI |
                           RIN_DRIVER_IMAGE_USES_MSIX | RIN_DRIVER_IMAGE_EXPERIMENTAL)) != 0 ||
        !(header->flags & RIN_DRIVER_IMAGE_RELOCATABLE) || (header->flags & RIN_DRIVER_IMAGE_USES_MSIX) && !(header->flags & RIN_DRIVER_IMAGE_USES_MSI) ||
        ((header->flags & RIN_DRIVER_IMAGE_SIGNED) != 0 &&
         (!range_u64(header->signature_offset, header->signature_size, blob->size) ||
          header->signature_offset + header->signature_size != blob->size)) ||
        ((header->flags & RIN_DRIVER_IMAGE_SIGNED) == 0 &&
         (header->signature_offset != 0 || header->signature_size != 0)) ||
        header->section_table_offset < sizeof(RinDriverHeaderV3) ||
        !range_u64(header->section_table_offset, (uint64_t)header->section_count * sizeof(RinSectionV3), content_limit) ||
        !range_u64(header->match_table_offset, (uint64_t)header->match_count * sizeof(RinDriverMatchV3), content_limit) ||
        header->string_table_offset < sizeof(RinDriverHeaderV3) || header->string_table_size == 0 ||
        !range_u64(header->string_table_offset, header->string_table_size,
                   content_limit) ||
        overlap_u64(header->section_table_offset, (uint64_t)header->section_count * sizeof(RinSectionV3), header->match_table_offset, (uint64_t)header->match_count * sizeof(RinDriverMatchV3)) ||
        overlap_u64(header->section_table_offset, (uint64_t)header->section_count * sizeof(RinSectionV3), header->string_table_offset, header->string_table_size) ||
        overlap_u64(header->match_table_offset, (uint64_t)header->match_count * sizeof(RinDriverMatchV3), header->string_table_offset, header->string_table_size) ||
        !zero_bytes((const uint8_t *)header->reserved, sizeof(header->reserved)) ||
        verify_signature(blob->data, blob->size, header->signature_offset, header->signature_size,
                         header->signature_algorithm, header->hash_algorithm, header->content_hash,
        (header->flags & RIN_DRIVER_IMAGE_SIGNED) != 0, options->trust_key, options->allow_unsigned) != 0) return -1;
    sections = (const RinSectionV3 *)(blob->data + header->section_table_offset);
    strings = (const char *)(blob->data + header->string_table_offset);
    if (strings[0] != '\0') return -1;
    for (i = 0; i < header->section_count; ++i) {
        const RinSectionV3 *section = &sections[i];
        if ((section->type < RIN_IMAGE_SECTION_CODE || section->type > RIN_IMAGE_SECTION_BSS) &&
            section->type != RIN_IMAGE_SECTION_RELOCATIONS) return -1;
        if (section->reserved ||
            !power_of_two(section->alignment) || section->alignment > 0x200000 ||
            (section->virtual_address & (section->alignment - 1u)) != 0 ||
            !string_at(strings, header->string_table_size, section->name_offset) ||
            (section->type != RIN_IMAGE_SECTION_RELOCATIONS &&
             (!range_u64(section->virtual_address, section->memory_size, header->image_size) ||
              section->memory_size == 0 || section->file_size > section->memory_size)) ||
            (section->file_size && (section->file_offset < sizeof(RinDriverHeaderV3) || !range_u64(section->file_offset, section->file_size, content_limit))) ||
            (section->type != RIN_IMAGE_SECTION_RELOCATIONS &&
             (section->flags & RIN_IMAGE_SECTION_WRITE) && (section->flags & RIN_IMAGE_SECTION_EXECUTE))) return -1;
        if (section->type == RIN_IMAGE_SECTION_CODE) {
            ++code_count;
            code_section = section;
            if (section->flags != (RIN_IMAGE_SECTION_READ | RIN_IMAGE_SECTION_EXECUTE) || !section->file_size) return -1;
        } else if (section->type == RIN_IMAGE_SECTION_RODATA) {
            if (section->flags != RIN_IMAGE_SECTION_READ) return -1;
        } else if (section->type == RIN_IMAGE_SECTION_DATA || section->type == RIN_IMAGE_SECTION_BSS) {
            if (section->flags != (RIN_IMAGE_SECTION_READ | RIN_IMAGE_SECTION_WRITE) ||
                (section->type == RIN_IMAGE_SECTION_BSS && (section->file_size || section->file_offset))) return -1;
        } else if (section->type == RIN_IMAGE_SECTION_RELOCATIONS) {
            if (!section->file_size || section->memory_size ||
                section->flags != RIN_IMAGE_SECTION_DISCARDABLE ||
                section->file_size % sizeof(RinRelocationV3) != 0) return -1;
            if (relocations) return -1;
            relocations = section;
        } else return -1;
        if (section->file_size &&
            (overlap_u64(section->file_offset, section->file_size,
                         header->section_table_offset,
                         (uint64_t)header->section_count * sizeof(RinSectionV3)) ||
             overlap_u64(section->file_offset, section->file_size,
                         header->match_table_offset,
                         (uint64_t)header->match_count * sizeof(RinDriverMatchV3)) ||
             overlap_u64(section->file_offset, section->file_size,
                         header->string_table_offset,
                         header->string_table_size))) return -1;
    }
    if (code_count != 1 || !code_section || !section_contains(code_section, header->start_rva, 1) ||
        (header->probe_rva >= header->image_size && header->probe_rva != 0) ||
        (header->stop_rva >= header->image_size && header->stop_rva != 0) ||
        (header->remove_rva >= header->image_size && header->remove_rva != 0) ||
        (header->power_rva >= header->image_size && header->power_rva != 0)) return -1;
    matches = (const RinDriverMatchV3 *)(blob->data + header->match_table_offset);
    for (i = 0; i < header->match_count; ++i) {
        if (matches[i].bus_type == RIN_DRIVER_BUS_ANY || matches[i].flags == 0 ||
            (matches[i].flags & ~(RIN_DRIVER_MATCH_VENDOR_DEVICE |
                                  RIN_DRIVER_MATCH_SUBSYSTEM |
                                  RIN_DRIVER_MATCH_CLASS |
                                  RIN_DRIVER_MATCH_REVISION)) != 0 ||
            ((matches[i].flags & RIN_DRIVER_MATCH_CLASS) && matches[i].class_mask == 0) ||
            (matches[i].required_resources & ~header->required_resources) != 0 ||
            matches[i].reserved0 || matches[i].reserved1 || !zero_bytes((const uint8_t *)matches[i].reserved, sizeof(matches[i].reserved)) ||
            !string_at(strings, header->string_table_size, matches[i].name_offset)) return -1;
    }
    if (relocations) {
        const RinRelocationV3 *table =
            (const RinRelocationV3 *)(blob->data + relocations->file_offset);
        uint64_t count = relocations->file_size / sizeof(*table);
        for (i = 0; i < count; ++i) {
            uint64_t width = table[i].type == RIN_IMAGE_RELOCATION_ABS64 ? 8u : 4u;
            if (table[i].reserved0 || table[i].reserved1 || !table[i].virtual_address ||
                (i && table[i].virtual_address <= table[i - 1].virtual_address) ||
                (table[i].type != RIN_IMAGE_RELOCATION_ABS64 &&
                 table[i].type != RIN_IMAGE_RELOCATION_ABS32U &&
                 table[i].type != RIN_IMAGE_RELOCATION_ABS32S) ||
                (header->architecture == RIN_ARCH_X86 && width != 4u) ||
                !range_u64(table[i].virtual_address, width, header->image_size) ||
                (i && table[i - 1].virtual_address +
                         (table[i - 1].type == RIN_IMAGE_RELOCATION_ABS64 ? 8u : 4u) >
                     table[i].virtual_address)) return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    Options options = {0};
    Blob image = {0};
    int i, result;
    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--kind") == 0 && i + 1 < argc) options.kind = argv[++i];
        else if (strcmp(argv[i], "--arch") == 0 && i + 1 < argc) options.arch = argv[++i];
        else if (strcmp(argv[i], "--trust-key") == 0 && i + 1 < argc) options.trust_key = argv[++i];
        else if (strcmp(argv[i], "--allow-unsigned") == 0) options.allow_unsigned = 1;
        else if (strcmp(argv[i], "--exact-dependencies") == 0) options.exact_dependencies = 1;
        else if (strcmp(argv[i], "--exact-exports") == 0) options.exact_exports = 1;
        else if (strcmp(argv[i], "--exact-imports") == 0) options.exact_imports = 1;
        else if (strcmp(argv[i], "--require-dependency") == 0 && i + 1 < argc && options.required_dependency_count < 64) options.required_dependencies[options.required_dependency_count++] = argv[++i];
        else if (strcmp(argv[i], "--require-export") == 0 && i + 1 < argc && options.required_export_count < 128) options.required_exports[options.required_export_count++] = argv[++i];
        else if (strcmp(argv[i], "--require-import") == 0 && i + 1 < argc && options.required_import_count < 128) options.required_imports[options.required_import_count++] = argv[++i];
        else if (!options.image_path && argv[i][0] != '-') options.image_path = argv[i];
        else { usage(stderr); return 2; }
    }
    if (!options.kind || !options.image_path ||
        (strcmp(options.kind, "executable") != 0 && strcmp(options.kind, "service") != 0 &&
         strcmp(options.kind, "library") != 0 && strcmp(options.kind, "driver") != 0) ||
        (options.allow_unsigned && options.trust_key)) {
        usage(stderr);
        return 2;
    }
    if (read_file(options.image_path, &image) != 0) return 2;
    result = strcmp(options.kind, "driver") == 0 ? validate_driver(&image, &options) : validate_rin(&image, &options);
    if (result == 0) printf("rinvalidate: accepted %s\n", options.image_path);
    else fprintf(stderr, "rinvalidate: rejected %s\n", options.image_path);
    free(image.data);
    return result == 0 ? 0 : 1;
}
