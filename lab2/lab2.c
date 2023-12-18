#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

int main(int argc, char *argv[])
{
	char *path = argv[1];
	DIR *dir;
	if (!(dir = opendir(argv[1]))) {
		perror("Error");
		exit(1);
	}
	struct dirent *dp;
	while ((dp = readdir(dir)) != NULL) {
		if (dp->d_name[0] != '.') {
			char *fullpath = malloc(strlen(path) + strlen(dp->d_name) + 2);
			strcpy(fullpath, path);
			strcat(fullpath, "/");
			strcat(fullpath, dp->d_name);
			if (dp->d_type == DT_DIR) {
				char **new_argv = malloc (3 * sizeof(char *));
				new_argv[0] = argv[0];
				new_argv[1] = fullpath;
                new_argv[2] = argv[2];
				main(2, new_argv);
				free(new_argv);
			}
			else {
                FILE *search;
                if (!(search = fopen(fullpath, "r"))) {
                    perror("Error");
                }
                char line[4096];
                while (fgets(line, sizeof(line), search)) {
                    if (strstr(line, argv[2])) {
                        printf("%s\n", fullpath);
                        return 0;
                    }
                }
                fclose(search);
            }
			free (fullpath);
		}
	}
	closedir(dir);
	return 0;
}
