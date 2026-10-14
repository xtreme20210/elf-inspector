#include <stdio.h>
#include <stdint.h>
#include <elf.h>

int inspect64(FILE *file, int endian) {
    Elf64_Ehdr header;
    if (endian != 1) {
        fprintf(stderr, "Wrong endianness\n z ");
        return 1;
    }
    fseek(file, 0, SEEK_SET);
    fread(&header, sizeof(header), 1, file);

    switch(header.e_type) {
        case ET_REL:
            printf("object %u\n", header.e_type);
            break;
        case ET_EXEC:
            printf("executable %u\n", header.e_type);
            break;
        case ET_DYN:
            printf("shared object %u\n", header.e_type);
            break;
        case ET_CORE:
            printf("core dump %u\n", header.e_type);
            break;
        default:
            printf("unknown type %u\n", header.e_type);
            break;
    }

    switch(header.e_machine) {
        case EM_386:
            printf("Intel x86 %u\n", header.e_machine);
            break;
        case EM_ARM:
            printf("ARM 32 bit %u\n", header.e_machine);
            break;
        case EM_AARCH64:
            printf("ARM 64 bit %u\n", header.e_machine);
            break;
        case EM_X86_64:
            printf("AMD64 %u\n", header.e_machine);
            break;
        default:
            printf("unknown architecture %u\n", header.e_machine);
            break;
    }

    struct Field {
        const char *name;
        unsigned long long value;
        int printType;
    };

    enum printType {
        HEX = 1,
        DECIMAL = 2
    };

    struct Field extraPrints[] = {
        {"e_entry", header.e_entry, HEX},
        {"e_phoff", header.e_phoff, HEX},
        {"e_shoff", header.e_shoff, HEX},
        {"e_phentsize", header.e_phentsize, HEX},
        {"e_phnum", header.e_phnum, DECIMAL},
        {"e_shnum", header.e_shnum, DECIMAL}
    };

    int count = sizeof(extraPrints) / sizeof(extraPrints[0]);

    for (int i = 0; i < count; i++) {
        switch(extraPrints[i].printType) {
            case 1:
                printf("%s = %llx\n", extraPrints[i].name, extraPrints[i].value);
                break;
            case 2:
                printf("%s = %llu\n", extraPrints[i].name, extraPrints[i].value);
                break;
        };
    }

    Elf64_Phdr segments;
    if (header.e_phentsize != sizeof(segments)) {
        fprintf(stderr, "Error loading segments\n");
        return 1;
    }

    if (fseek(file, header.e_phoff, SEEK_SET) !=0) {
        fprintf(stderr,"error seeking segments\n");
        return 1;
    }

    for (int i = 0; i < header.e_phnum; i++) {
        if (fread(&segments, sizeof(segments), 1, file) != 1) {
            fprintf(stderr, "error reading segments\n");
            return 1;
        }
        switch(segments.p_type) {
            case PT_NULL:
                printf("unused entry, %u\n", segments.p_type);
                break;
            case PT_LOAD:
                printf("loaded into memory, %u\n", segments.p_type);
                break;
            case PT_DYNAMIC:
                printf("dynamic linking info, %u\n", segments.p_type);
                break;
            case PT_INTERP:
                printf("program interpreter, %u\n", segments.p_type);
                break;
            case PT_NOTE:
                printf("note, %u\n", segments.p_type);
                break;
            case PT_PHDR:
                printf("header table, %u\n", segments.p_type);
                break;
            case PT_TLS:
                printf("thread local storage, %u\n", segments.p_type);
                break;
            case PT_GNU_EH_FRAME:
                printf("gnu exception handling, %u\n", segments.p_type);
                break;
            case PT_GNU_STACK:
                printf("gnu stack, %u\n", segments.p_type);
                break;
            case PT_GNU_RELRO:
                printf("made ro after relocation, %u\n", segments.p_type);
                break;
            case PT_GNU_PROPERTY:
                printf("gnu exec properties, %u\n", segments.p_type);
                break;
            default:
                printf("unknown type, %x\n", segments.p_type);
                break;
        }

        struct Field segPrints[] = {
            {"p_offset", segments.p_offset, HEX},
            {"p_vaddr", segments.p_vaddr, HEX},
            {"p_paddr", segments.p_paddr, HEX},
            {"p_filesz", segments.p_filesz, HEX},
            {"p_memsz", segments.p_memsz, HEX},
            {"p_align", segments.p_align, HEX},
        };

        int count = sizeof(segPrints) / sizeof(segPrints[0]);

        for (int i = 0; i < count; i++) {
            switch(segPrints[i].printType) {
                case HEX:
                    printf("    %s = %llx\n", segPrints[i].name, segPrints[i].value);
                    break;
                case DECIMAL:
                    printf("    %s = %llu\n", segPrints[i].name, segPrints[i].value);
                    break;
            };
        }
        if(segments.p_flags & PF_R) {
            printf("    Read\n");
        } 
        if (segments.p_flags & PF_W) {
            printf("    Write\n");
        } 
        if (segments.p_flags & PF_X) {
            printf("    Execute\n");
        }
    }
}

int main (int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage error\n");
        return 1;
    }
    FILE *file = fopen(argv[1], "rb");
    if (file == NULL) {
        fprintf(stderr, "Failed to open file\n");
        return 1;
    }

    unsigned char binary[32];
    size_t bytesRead = fread(binary, 1, sizeof(binary), file);

    if (bytesRead != sizeof(binary)) {
        fprintf(stderr, "Error reading file\n");
        fclose(file);
        return 1;
    }

    if (binary[0] != 0x7f || binary[1] != 'E' || binary[2] != 'L' || binary[3] != 'F') {
        fprintf(stderr, "\nNot an ELF file\n");
        return 1;
    }

    for (int i = 0; i < 16; i++) {
        printf("%02x ", binary[i]);
    }

    int bit;
    int endian;

    if (binary[4] == 1) {
        printf("\n32 bit\n");
        bit = 32;
    } else if (binary[4] == 2) {
        printf("\n64 bit\n");
        bit = 64;
    } else {
        fprintf(stderr, "Invalid ELF file type\n");
    }
    
    if (binary[5] == 1) {
        printf("little endian\n");
        endian = 1;
    } else if (binary[5] == 2) {
        printf("big endian\n");
        endian = 2;
    } else {
        fprintf(stderr, "Invalid endianness\n");
    }

    if (bit == 32) {
        fprintf(stderr, "32 bit not supported yet");
    } else if (bit == 64) {
       inspect64(file, endian);
    } else {
        fprintf(stderr, "Invalid bit number");
    }

    fclose(file);
    return 0;
}
