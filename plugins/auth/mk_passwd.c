/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>

#include "mk_list.h"
#include "mk_macros.h"
#include "mk_memory.h"
#include "mk_string.h"
#include "sha1.h"
#include "base64.h"

#define MAX_LINE_LEN 256

/* Store a file as a linked list of its lines */
static struct mk_list passwd_file;

/* Load file to memory from disk
 * If create_file == MK_TRUE, the file will be rewritten */
void read_file(char *filename, int create_file)
{
    FILE *filein = fopen(filename, "r");
    char line[MAX_LINE_LEN];
    struct mk_string_line *entry;

    mk_list_init(&passwd_file);

    if (filein == NULL && create_file == MK_FALSE) {
        printf("Error opening file %s\n", filename);
        exit(1);
    }

    if (filein == NULL || create_file == MK_TRUE) {
        if (filein != NULL)
            fclose(filein);
        return;
    }

    while (fgets(line, MAX_LINE_LEN, filein) != NULL) {
        entry = mk_mem_malloc(sizeof(*entry));
        entry->val = mk_string_dup(line);
        entry->len = strlen(line);
        mk_list_add(&entry->_head, &passwd_file);
    }
    fclose(filein);
}

/* Store data to disk */
void dump_file(char *filename)
{
    FILE *fileout = fopen(filename, "w");
    struct mk_list *it, *tmp;
    struct mk_string_line *entry;

    mk_list_foreach_safe(it, tmp, &passwd_file) {
        entry = mk_list_entry(it, struct mk_string_line, _head);
        fprintf(fileout, "%s", entry->val);
        mk_list_del(&entry->_head);
        mk_mem_free(entry->val);
        mk_mem_free(entry);
    }
    fclose(fileout);
}

/* Return sha1 hash of password
 * A new line is appended at the hash */
unsigned char *sha1_hash(const char *password)
{

    unsigned char sha_hash[20];
    blk_SHA_CTX sha;

    blk_SHA1_Init(&sha);
    blk_SHA1_Update(&sha, password, strlen(password));
    blk_SHA1_Final(sha_hash, &sha);

    return base64_encode(sha_hash, 20, NULL);
}

void update_user(const char *username, const char *password, int create_user)
{
    struct mk_list *it, *tmp;
    struct mk_string_line *entry;
    unsigned char *hash_passwd;
    int i;
    unsigned long len;

    mk_list_foreach_safe(it, tmp, &passwd_file) {
        entry = mk_list_entry(it, struct mk_string_line, _head);
        for (i = 0; entry->val[i] != '\0' && entry->val[i] != ':' && username[i] != '\0' && entry->val[i] == username[i]; i++);
        if (entry->val[i] != ':' || username[i] != '\0')
            continue;

        /* Found a match */

        /* Delete user */
        if (create_user == MK_FALSE) {
            printf("[-] Deleting user %s\n", username);
            mk_list_del(&entry->_head);
            mk_mem_free(entry->val);
            mk_mem_free(entry);
            return;
        }

        /* Update user */
        printf("[+] Password changed for user %s\n", username);
        hash_passwd = sha1_hash(password);
        mk_mem_free(entry->val);
        entry->val = NULL;
        mk_string_build(&entry->val, &len, "%s:{SHA1}%s", username, hash_passwd);
        free(hash_passwd);

        return;
    }

    /* Create user */
    if (create_user == MK_TRUE) {
        printf("[+] Adding user %s\n", username);
        entry = mk_mem_malloc(sizeof(*entry));
        entry->val = NULL;
        hash_passwd = sha1_hash(password);
        mk_string_build(&entry->val, &len, "%s:{SHA1}%s", username, hash_passwd);
        free(hash_passwd);

        mk_list_add(&entry->_head, &passwd_file);
    }
}

static void print_help(int full_help)
{
    printf("Usage: mkpasswd [-c] -b filename username password\n\tCreate or update an mkpasswd file\n");
    if (full_help == MK_TRUE) {
        printf("\nOptions:\n");
        printf("  -h, --help\tshow this help message and exit\n");
        printf("  -b\t\tBatch mode; password is passed on the command line IN THE CLEAR.\n");
        printf("  -c\t\tCreate a new mkpasswd file, overwriting any existing file.\n");
        printf("  -D\t\tRemove the given user from the password file.\n");
    }
}

int main(int argc, char *argv[])
{
    int opt;
    int create_user = MK_TRUE;
    int create_file = MK_FALSE;
    int show_help = MK_FALSE;
    int batch_mode = MK_FALSE;
    char *filename = NULL;
    char *username = NULL;
    char *password = NULL;

    /* Command line options */
    static const struct option long_opts[] = {
        {"batch", no_argument, NULL, 'b'},
        {"create", no_argument, NULL, 'c'},
        {"delete_user", no_argument, NULL, 'D'},
        {"help", no_argument, NULL, 'h'},
    };

    /* Parse options */
    while ((opt = getopt_long(argc, argv, "hbDc", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'b':
                batch_mode = MK_TRUE;
                break;
            case 'c':
                create_file = MK_TRUE;
                break;
            case 'D':
                create_user = MK_FALSE;
                break;
            case 'h':
                show_help = MK_TRUE;
                break;
        }
    }

    /* Retrieve filename, username and password */
    while (optind < argc) {
        if (filename == NULL)
            filename = argv[optind++];
        else if (username == NULL)
            username = argv[optind++];
        else if (password == NULL)
            password = argv[optind++];
    }

    if (show_help == MK_TRUE) {
        print_help(MK_TRUE);
        exit(0);
    }

    /* If delete_user option is provided, do not provide a password */
    if ((password != NULL) ^ (create_user == MK_TRUE)) {
        print_help(MK_FALSE);
        exit(1);
    }

    if (batch_mode == MK_FALSE) {
        printf("Only batch mode is supported\n");
        exit(1);
    }

    /* Process request */
    read_file(filename, create_file);
    update_user(username, password, create_user);
    dump_file(filename);

    return 0;
}
