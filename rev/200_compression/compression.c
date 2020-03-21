#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct file_content {
    long size;
    char * buffer;
} FileContent;

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

void writeFile(char * file, char * content, long len) {
    FILE *fp;
    fp = fopen(file, "w");
    fwrite(content, 1, len, fp);
    fclose(fp);
}

typedef struct byte_location {
    long size;
    long * locations;
} ByteLocations;

void init_locations(ByteLocations * l) {
    l->size = 0;
    l->locations = malloc(sizeof(long) * l->size);
}

void init_locations_size(ByteLocations * l, long size) {
    l->size = size;
    l->locations = malloc(sizeof(long) * l->size);
}

void add_location(ByteLocations * l, long location) {
    l->size++;
    l->locations = realloc(l->locations, sizeof(long) * l->size);
    l->locations[l->size-1] = location;
}

typedef struct compressed {
    long size;
    ByteLocations * bytes[256];
} Compressed;

typedef struct header {
    long size;
    long count_start[256];
    long count_end[256];
} Header;

FileContent compress(unsigned char * buffer, long len) {
    Compressed c;
    c.size = len;
    for(unsigned long i = 0; i < 256; i++) {
        c.bytes[i] = malloc(sizeof(ByteLocations));
        init_locations(c.bytes[i]);
    }

    for(unsigned long i = 0; i < c.size; i++) {
        add_location(c.bytes[buffer[i]], i);
    }

    // Convert to string

    long header_size = sizeof(Header);
    long size = header_size + c.size * sizeof(long);
    char * r = malloc(size);

    Header header;
    header.size = c.size;


    // copy data
    long offset = sizeof(Header);
    for(unsigned long i = 0; i < 256; i++) {
        header.count_start[i] = offset;
        for(long j = 0; j < c.bytes[i]->size; j++) {
            memcpy(r + offset, &c.bytes[i]->locations[j], sizeof(long));
            offset += sizeof(long);
        }
        header.count_end[i] = offset;
    }

    // copy header
    memcpy(r, &header, sizeof(Header));

    FileContent result;
    result.buffer = r;
    result.size = size;

    return result;
}

long main(int argc, char ** argv) {
    if(argc < 3) {
        printf("./compression <input> <output>\n");
        exit(1);
    }

    FileContent fc = readFile(argv[1]);

    FileContent r = compress(fc.buffer, fc.size);
    writeFile(argv[2], r.buffer, r.size);

    return 0;
}
