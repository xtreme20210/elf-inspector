#include <stdio.h>
#include <stdint.h>
#include <elf.h>

enum printType {
    HEX = 1,
    DECIMAL = 2
};

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

static const struct Cases sectionValues[] = {
    {SHT_NULL, "unused section"},
    {SHT_PROGBITS, "program data"},
    {SHT_SYMTAB, "symbol table"},
    {SHT_STRTAB, "string table"},
    {SHT_RELA, "relocations with addends"},
    {SHT_HASH, "symbol hash table"},
    {SHT_DYNAMIC, "dynamic linking information"},
    {SHT_NOTE, "note"},
    {SHT_NOBITS, "occupies no file space"},
    {SHT_REL, "relocations without addends"},
    {SHT_DYNSYM, "dynamic symbol table"},
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

void printLoop(const struct Cases arr[], size_t size, uint32_t value, const char *printDefault) {
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
}

void printFields(struct Field arr[], size_t arrSize) {
    for (int i = 0; i < arrSize; i++) {
        switch(arr[i].printType) {
            case 1:
                printf("    %s = 0x%llx\n", arr[i].name, arr[i].value);
                break;
            case 2:
                printf("    %s = %llu\n", arr[i].name, arr[i].value);
                break;
        };
    }
}

int inspectSections64(FILE *file, const Elf64_Ehdr *header) {

    Elf64_Shdr sections;
    fseek(file, header->e_shoff, SEEK_SET);


    struct Field sectionFields[] = {
        {"e_shoff", header->e_shoff, HEX},
        {"e_shentsize", header->e_shentsize, HEX},
        {"e_shnum", header->e_shnum, DECIMAL}
    };

    size_t secValuesSize = sizeof(sectionValues) / sizeof(sectionValues[0]);

    for (int i=0; i < header->e_shnum; i++) {
        fseek(file, (header->e_shoff + i * header->e_shentsize), SEEK_SET);
        fread(&sections, sizeof(sections), 1, file);
        printLoop(sectionValues, secValuesSize, sections.sh_type, "unknown type");
        Elf64_Shdr stringTab;
        uint64_t strTabOffset = header->e_shoff + (header->e_shstrndx * header->e_shentsize);
        fseek(file, strTabOffset, SEEK_SET);
        fread(&stringTab, sizeof(stringTab), 1, file);
        uint64_t nameOffset = sections.sh_name + stringTab.sh_offset;
        fseek(file, nameOffset, SEEK_SET);
        char name[256];
        int character = 0;
        int nameLength = 0;
        do {
            character = fgetc(file);
            if (character == EOF) {
                break;
            }
            name[nameLength]= (char)character;
            nameLength++;
        } while (character != '\0' && character != EOF && nameLength < stringTab.sh_size && nameLength<256);
        printf("%.*s", nameLength, name);
        nameLength = 0;
        printf ("\n");

        struct Field sFields[] = {
            {"sh_addr", sections.sh_addr, HEX},
            {"sh_offset", sections.sh_offset, HEX},
            {"sh_size", sections.sh_size, HEX},
            {"sh_addralign", sections.sh_addralign, DECIMAL},
            {"sh_flags", sections.sh_flags, HEX}
        };

        size_t sFieldsSize = sizeof(sFields) / sizeof(sFields[0]);

        printFields(sFields, sFieldsSize);

            if(sections.sh_flags & SHF_WRITE) {
                printf("    writable\n");
            } 
            if (sections.sh_flags & SHF_ALLOC) {
                printf("    occupies memory\n");
            } 
            if (sections.sh_flags & SHF_EXECINSTR) {
                printf("    executable instructions\n");
            }
            if(sections.sh_flags & SHF_MERGE) {
                printf("    mergeable data\n");
            } 
            if (sections.sh_flags & SHF_STRINGS) {
                printf("    strings\n");
            } 
            if (sections.sh_flags & SHF_TLS) {
                printf("    thread local storage\n");
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

    struct Field extraPrints[] = {
        {"e_entry", header.e_entry, HEX},
        {"e_phoff", header.e_phoff, HEX},
        {"e_shoff", header.e_shoff, HEX},
        {"e_phentsize", header.e_phentsize, HEX},
        {"e_phnum", header.e_phnum, DECIMAL},
        {"e_shnum", header.e_shnum, DECIMAL}
    };

    size_t emachineSize = sizeof(emachine) / sizeof(emachine[0]);
    printLoop(emachine, emachineSize, header.e_machine, "unknown architecture");

    int extraPrintsSize = sizeof(extraPrints) / sizeof(extraPrints[0]);

    size_t etypeSize = sizeof(etype) / sizeof(etype[0]);
    printf("ELF header: \n");
    printLoop(etype, etypeSize, header.e_type, "unknown type");
    printFields(extraPrints, extraPrintsSize);

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
            printLoop(ptype, ptypeSize, segments.p_type, "unknown type");
            printFields(segPrints, segPrintsSize);

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

    inspectSections64(file, &header);

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

    int bit = 0;
    int endian = 0;

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
