#include <stdio.h>
#include <string.h>

int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};


	int filesToProccess = 10;


	/* File 0-10 Creation and write (Creation, Write) */

	for (i = 0; i < filesToProccess; i++) {

		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}


	/* File open with append mode and write (Read,Write)*/
	for (i = 0; i < filesToProccess; i++) {

		file = fopen(filenames[i], "a");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}


	/* File 0-10 Read Only (Read) */

	for(int i = 0; i < filesToProccess; i++){

		file = fopen(filenames[i], "r");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			fclose(file);
		}

	}

	/* Previous content is going to be erased file already exists (Delete, Write)*/
	for(int i = 0; i < filesToProccess; i++){

		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}





}
