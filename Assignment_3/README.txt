----------------------------------------------------------------------------------------
Assignment 3 - Manos Ieronymakis 2015030136
----------------------------------------------------------------------------------------
                                Ubuntu/GCC Version
----------------------------------------------------------------------------------------
gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0
----------------------------------------------------------------------------------------
                                What did I implement ?
----------------------------------------------------------------------------------------
Everything.
----------------------------------------------------------------------------------------
                                Explanation of tool
----------------------------------------------------------------------------------------
logger.c file contains wrappers for functions fopen() and fwrite().
----------------------------------------------------------------------------------------
                                fopen() Wrapper function
----------------------------------------------------------------------------------------

At the beggining I setup the standard GNU function fopen() and the return value for
the file path and mode given as input. After that I check the file path given.

This check is done because I want to use the standard fopen() for some files and the
modified fopen() for some others.

More specific, I don't want the encryption tool files to use the modified fopen(),
because that creates a never ending loop of fopen() calls.

After that I get the user id of the person using the executable produced.

I also get the datetime of execution and the access type that was used in order to open
the file.

I check if the user got denied access and save it for logging later.

I get the full path of the file (not the relative inside the folder).

Then in order to produce the MD5 hash I need the file data and length.
If someone got denied access, for example using "w" permission that's not letting me
produce the MD5 hash, so I reopen the file with "r" permission in order to get the file
fingerprint. I still set fopen() return value to NULL in that case.

After all this is checked I get the file length by seeking to EOF.
I also read the whole file into a buffer.
With length and buffer I use MD5 functions of openssl to create the file hash (fingerprint).

I create the logging file named "file_logging.log" where I save the following information
in this order for each fopen() call:

__________________________________________________________________________________________________________
|   UID  |   ACCESS_TYPE |   DENIED_ACCESS   |   ABSOLUTE_PATH_OF_FILE   |   FILE_HASH   |   DATETIME    |
__________________________________________________________________________________________________________

(I use chmod 0777 on logging file to give all users read/write/execute permissions )

Lastly I use the RSA encryption tool from Assignment 1 to encrypt the logging file using predefined private,
public keys.

(I use chmod 0777 on encrypted logging file to give all users read/write/execute permissions )

----------------------------------------------------------------------------------------
                                fwrite() Wrapper function
----------------------------------------------------------------------------------------

Similar with fopen() wrapper function, I firstly setup the standard GNU fwrite() function,

Then I get the basename/full path of file with only difference I get it from the file descriptor,

Then I do the same checks because I need the encryption tool to use only the standard fwrite()
,not the whole wrapper.

With the same method as fopen() I generate the MD5 Hash of the file.

Lastly I write the event with the same format as fopen() in the logging file.
Difference here is that the access type is set to 2 because fwrite() was used.

----------------------------------------------------------------------------------------
                                    ACCESS TYPE TABLE
----------------------------------------------------------------------------------------
    FOPEN PERMISSION MODE       |          FILE EXISTS          |       TYPE VALUE
----------------------------------------------------------------------------------------
            "r" "r+"            |               NO              |           1
----------------------------------------------------------------------------------------
            "r" "r+"            |               YES             |           1
----------------------------------------------------------------------------------------
            "w" "w+"            |               NO              |           0
----------------------------------------------------------------------------------------
            "w" "w+"            |               YES             |           3
----------------------------------------------------------------------------------------
            "a" "a+"            |               NO              |           2
----------------------------------------------------------------------------------------
            "a" "a+"            |               YES             |           2
----------------------------------------------------------------------------------------
            FWRITE()            |                               |           2
----------------------------------------------------------------------------------------



