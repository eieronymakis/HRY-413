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

	int filesToProccess = 8;

	/* File creation (file doesn't exist) & Write */
	for (i = 0; i < filesToProccess; i++) {
		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
	}

	/* Open as append & Write */
	for (i = 0; i < filesToProccess; i++) {
		file = fopen(filenames[i], "a+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
	}

	/* Open as read (No write) */
	for (i = 0; i < filesToProccess; i++) {
		file = fopen(filenames[i], "r");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			fclose(file);
		}
	}

	/* Open as write (file exists) so deletion (No write) */
	for (i = 0; i < filesToProccess; i++) {
		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			fclose(file);
		}
	}

}
