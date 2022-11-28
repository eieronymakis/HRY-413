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
                                Explanation of Logger tool
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
                        Sample Output of Logger & Monitoring Tool
----------------------------------------------------------------------------------------
Command order
----------------------------------------------------------------------------------------
1) make clean
2) make
3) make run
4) su malicious -c "make run" (Password -> 1111)
5) su malicious2 -c "make run" (Password -> 1111)
6) ./acmonitor -m
7) ./acmonitor -i file_0
----------------------------------------------------------------------------------------

----------------------------------------------------------------------------------------
file_logging.log contents
----------------------------------------------------------------------------------------

1000	0	0	file_0	d41d8cd98f00b204e9800998ecf8427e	Mon Nov 28 22:50:57 2022
1000	2	0	file_0	6eb512cb2557734c63f6fa15ef61ef9f	Mon Nov 28 22:50:57 2022
1000	0	0	file_1	d41d8cd98f00b204e9800998ecf8427e	Mon Nov 28 22:50:57 2022
1000	2	0	file_1	ba9d332813a722b273a95fa13dd88d94	Mon Nov 28 22:50:57 2022
1000	0	0	file_2	d41d8cd98f00b204e9800998ecf8427e	Mon Nov 28 22:50:57 2022
1000	2	0	file_2	92ed3b5f07b44bc4f70d0b24d5e1867c	Mon Nov 28 22:50:57 2022
1000	0	0	file_3	d41d8cd98f00b204e9800998ecf8427e	Mon Nov 28 22:50:57 2022
1000	2	0	file_3	797b373a9c4ec0d6de0a31a90b5bee8e	Mon Nov 28 22:50:57 2022
1000	0	0	file_4	d41d8cd98f00b204e9800998ecf8427e	Mon Nov 28 22:50:57 2022
1000	2	0	file_4	74a02cce629c5f4c0bd3c0b60db915e4	Mon Nov 28 22:50:57 2022
1000	0	0	file_5	d41d8cd98f00b204e9800998ecf8427e	Mon Nov 28 22:50:57 2022
1000	2	0	file_5	3d58b0ebc69908c51a9273135f3aac3f	Mon Nov 28 22:50:57 2022
1000	0	0	file_6	d41d8cd98f00b204e9800998ecf8427e	Mon Nov 28 22:50:57 2022
1000	2	0	file_6	045e4d119474a0ffe08e1632ca286c9c	Mon Nov 28 22:50:57 2022
1000	0	0	file_7	d41d8cd98f00b204e9800998ecf8427e	Mon Nov 28 22:50:57 2022
1000	2	0	file_7	1813845c8e402f8d0482a5d274dc5596	Mon Nov 28 22:50:57 2022
1000	2	0	file_0	6eb512cb2557734c63f6fa15ef61ef9f	Mon Nov 28 22:50:57 2022
1000	2	0	file_0	04fc4d2ea7482c83fa03849e832cee9b	Mon Nov 28 22:50:57 2022
1000	2	0	file_1	ba9d332813a722b273a95fa13dd88d94	Mon Nov 28 22:50:57 2022
1000	2	0	file_1	8cedd94df857eb09fef87fdfcb5ccc06	Mon Nov 28 22:50:57 2022
1000	2	0	file_2	92ed3b5f07b44bc4f70d0b24d5e1867c	Mon Nov 28 22:50:57 2022
1000	2	0	file_2	2f9be41593fc6899a96fb662d7a4c38c	Mon Nov 28 22:50:57 2022
1000	2	0	file_3	797b373a9c4ec0d6de0a31a90b5bee8e	Mon Nov 28 22:50:57 2022
1000	2	0	file_3	2ae1f3075bd5341e0f12f1a58f8643f4	Mon Nov 28 22:50:57 2022
1000	2	0	file_4	74a02cce629c5f4c0bd3c0b60db915e4	Mon Nov 28 22:50:57 2022
1000	2	0	file_4	ac5705929f64188b0714a94071474302	Mon Nov 28 22:50:57 2022
1000	2	0	file_5	3d58b0ebc69908c51a9273135f3aac3f	Mon Nov 28 22:50:57 2022
1000	2	0	file_5	8ae1c8b1ed1618cd2635ceceacb402c1	Mon Nov 28 22:50:57 2022
1000	2	0	file_6	045e4d119474a0ffe08e1632ca286c9c	Mon Nov 28 22:50:57 2022
1000	2	0	file_6	ba004691a8c7a15eea3933d99244b595	Mon Nov 28 22:50:57 2022
1000	2	0	file_7	1813845c8e402f8d0482a5d274dc5596	Mon Nov 28 22:50:57 2022
1000	2	0	file_7	13441bbfac4844580e920d0cbdb889fd	Mon Nov 28 22:50:57 2022
1000	2	0	file_0	04fc4d2ea7482c83fa03849e832cee9b	Mon Nov 28 22:50:57 2022
1000	2	0	file_1	8cedd94df857eb09fef87fdfcb5ccc06	Mon Nov 28 22:50:57 2022
1000	2	0	file_2	2f9be41593fc6899a96fb662d7a4c38c	Mon Nov 28 22:50:57 2022
1000	2	0	file_3	2ae1f3075bd5341e0f12f1a58f8643f4	Mon Nov 28 22:50:58 2022
1000	2	0	file_4	ac5705929f64188b0714a94071474302	Mon Nov 28 22:50:58 2022
1000	2	0	file_5	8ae1c8b1ed1618cd2635ceceacb402c1	Mon Nov 28 22:50:58 2022
1000	2	0	file_6	ba004691a8c7a15eea3933d99244b595	Mon Nov 28 22:50:58 2022
1000	2	0	file_7	13441bbfac4844580e920d0cbdb889fd	Mon Nov 28 22:50:58 2022
1000	3	0	file_0	d41d8cd98f00b204e9800998ecf8427e	Mon Nov 28 22:50:58 2022
1000	3	0	file_1	d41d8cd98f00b204e9800998ecf8427e	Mon Nov 28 22:50:58 2022
1000	3	0	file_2	d41d8cd98f00b204e9800998ecf8427e	Mon Nov 28 22:50:58 2022
1000	3	0	file_3	d41d8cd98f00b204e9800998ecf8427e	Mon Nov 28 22:50:58 2022
1000	3	0	file_4	d41d8cd98f00b204e9800998ecf8427e	Mon Nov 28 22:50:58 2022
1000	3	0	file_5	d41d8cd98f00b204e9800998ecf8427e	Mon Nov 28 22:50:58 2022
1000	3	0	file_6	d41d8cd98f00b204e9800998ecf8427e	Mon Nov 28 22:50:58 2022
1000	3	0	file_7	d41d8cd98f00b204e9800998ecf8427e	Mon Nov 28 22:50:58 2022

--------------------------------------------------------------
./acmonitor -m Output
--------------------------------------------------------------
Malicious Users : 
--------------------------------------------------------------
UID     |       User Name       |       Files
--------------------------------------------------------------
1001    |       malicious       |       file_0  file_1  file_2  file_3  file_4  file_5  file_6  file_7
1002    |       malicious2      |       file_0  file_1  file_2  file_3  file_4  file_5  file_6  file_7
--------------------------------------------------------------

-----------------------------------------------------------------------------
./acmonitor -i file_0 Output
-----------------------------------------------------------------------------
File file_0 Accessed By :
-----------------------------------------------------------------------------
UID     |       User Name               |       Times
-----------------------------------------------------------------------------
1000    |       user                    |       6
1001    |       malicious               |       4
1002    |       malicious2              |       4
-----------------------------------------------------------------------------
Original file MD5 Hash (fingerprint) :  d41d8cd98f00b204e9800998ecf8427e
-----------------------------------------------------------------------------
Mofications done by users :
-----------------------------------------------------------------------------
UID     |       User Name               |       Times
-----------------------------------------------------------------------------
1000    |       user                    |       3
1001    |       malicious               |       0
1002    |       malicious2              |       0
-----------------------------------------------------------------------------