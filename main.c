#include <stdio.h>
#include <stdint.h>
#include <elf.h>

struct Cases {
    unsigned long long value;
    const char *printInfo;
};

struct Field {
    const char *name;
    unsigned long long value;
    int printType;
};

static const struct Cases emachine[] = {
    {EM_386, "Intel x86"},
    {EM_ARM, "ARM 32 bit"},
    {EM_AARCH64, "ARM 64 bit"},
    {EM_X86_64, "AMD 64"}
};

static const struct Cases etype[] = {
    {ET_REL, "object"},
    {ET_EXEC, "executable"},
    {ET_DYN, "shared object / PIE"},
    {ET_CORE, "core dump"}
};

static const struct Cases ptype[] = {
    {PT_NULL, "unused entry"},
    {PT_LOAD, "loaded into memory"},
    {PT_DYNAMIC, "dynamic linking info"},
    {PT_INTERP, "program interpreter"},
    {PT_NOTE, "note"},
    {PT_PHDR, "header table"},
    {PT_TLS, "thread local storage"},
    {PT_GNU_EH_FRAME, "gnu exception handling"},
    {PT_GNU_STACK, "gnu stack"},
    {PT_GNU_RELRO, "made ro after relocation"},
    {PT_GNU_PROPERTY, "gnu exec properties"}
};

void printLoop(const struct Cases arr[], size_t size, uint32_t value, const char *printDefault, struct Field valarr[], size_t valarrSize) {
    int count = 0;
    for (int i=0; i < size; i++) {
        if (arr[i].value == value) {
            printf("%s, %u\n", arr[i].printInfo, value);
            count++;
        }
    }
    if (count == 0) {
        printf("%s, %u\n", printDefault, value);
    }
    if (valarrSize !=0) {
        for (int i = 0; i < valarrSize; i++) {
            switch(valarr[i].printType) {
                case 1:
                    printf("    %s = 0x%llx\n", valarr[i].name, valarr[i].value);
                    break;
                case 2:
                    printf("    %s = %llu\n", valarr[i].name, valarr[i].value);
                    break;
            };
        }
    }
}

int inspect64(FILE *file, int endian) {
    Elf64_Ehdr header;
    if (endian != 1) {
        fprintf(stderr, "Wrong endianness\n");
        return 1;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Error seeking");
        return 1;
    }

    if (fread(&header, sizeof(header), 1, file) != 1) {
        fprintf(stderr, "Error reading ELF file");
        return 1;
    }


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

    size_t emachineSize = sizeof(emachine) / sizeof(emachine[0]);
    printLoop(emachine, emachineSize, header.e_machine, "unknown architecture", extraPrints, 0);

    int extraPrintsSize = sizeof(extraPrints) / sizeof(extraPrints[0]);

    size_t etypeSize = sizeof(etype) / sizeof(etype[0]);
    printf("ELF header: \n");
    printLoop(etype, etypeSize, header.e_type, "unknown type", extraPrints, extraPrintsSize);

    if (header.e_phnum > 0) {
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

            struct Field segPrints[] = {
                {"p_offset", segments.p_offset, HEX},
                {"p_vaddr", segments.p_vaddr, HEX},
                {"p_paddr", segments.p_paddr, HEX},
                {"p_filesz", segments.p_filesz, HEX},
                {"p_memsz", segments.p_memsz, HEX},
                {"p_align", segments.p_align, HEX},
            };

            int segPrintsSize = sizeof(segPrints) / sizeof(segPrints[0]);

            size_t ptypeSize = sizeof(ptype) / sizeof(ptype[0]);
            printLoop(ptype, ptypeSize, segments.p_type, "unknown type", segPrints, segPrintsSize);

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
    return 0;
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
    }
    
    if (binary[5] == 1) {
        printf("little endian\n");
        endian = 1;
    } else if (binary[5] == 2) {
        printf("big endian\n");
        endian = 2;
    } else {
        fprintf(stderr, "Invalid endianness\n");
        return 1;
    }

    if (bit == 32) {
        fprintf(stderr, "32 bit not supported yet\n");
        return 1;
    } else if (bit == 64) {
       int ec = inspect64(file, endian);
       if (ec==1) {
        fprintf(stderr, "Error inspecting ELF");
        fclose(file);
        return 1;
       }
    } else {
        fprintf(stderr, "Invalid bit number\n");
        fclose(file);
        return 1;
    }

    fclose(file);
    return 0;
}
