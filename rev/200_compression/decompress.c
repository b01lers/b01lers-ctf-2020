#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct file_content {
    long size;
    unsigned char * buffer;
} FileContent;

typedef struct byte_location {
    long size;
    long * locations;
} ByteLocations;

typedef struct compressed {
    long size;
    ByteLocations * bytes[256];
} Compressed;

typedef struct header {
    long size;
    long count_start[256];
    long count_end[256];
} Header;

FileContent readFile(char * f) {
    long c;
    FILE *file;
    file = fopen(f, "r");
    long size = 100;
    char * str = malloc(size);
    long i = 0;
    if(file) {
        while((c = getc(file)) != EOF) {
            str[i] = c;
            i++;
            if(i >= size - 1) {
                size = size * 2;
                str = realloc(str, size);
            }
        }
        str[i] = '\0';
        fclose(file);
    }
    FileContent r;
    r.buffer = str;
    r.size = i;
    return r;
}

void init_locations_size(ByteLocations * l, long size) {
    l->size = size;
    l->locations = malloc(sizeof(long) * l->size);
}

Compressed string_to_compressed(char * c) {
    Compressed r;

    Header header;
    memcpy(&header, c, sizeof(Header));

    r.size = header.size;

    long offset = sizeof(Header);
    for(unsigned long i = 0; i < 256; i++) {
        r.bytes[i] = malloc(sizeof(ByteLocations));
        init_locations_size(r.bytes[i], (header.count_end[i] - header.count_start[i])/sizeof(long));

        memcpy(r.bytes[i]->locations, c + header.count_start[i] , r.bytes[i]->size * sizeof(long));
    }

    return r;
}

FileContent decompress(Compressed c) {
    char * r = malloc(c.size);
    for(unsigned long i = 0; i < 256; i++) {
        for(unsigned long j = 0; j < c.bytes[i]->size; j++) {
            r[c.bytes[i]->locations[j]] = (unsigned char)i;
        }
    }

    FileContent result;
    result.buffer = r;
    result.size = c.size;
    return result;
}

long main(int argc, char ** argv) {
    if(argc < 2) {
        printf("./decompress <input>\n");
        exit(1);
    }

    FileContent fc = readFile(argv[1]);

    FileContent r = decompress(string_to_compressed(fc.buffer));

    write(1, r.buffer, r.size);
    printf("\n");

    return 0;
}
