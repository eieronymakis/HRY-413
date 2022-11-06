Command Explanation:
--------------------------------------------------------------------------------------
openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout mycert.pem -out mycert.pem
--------------------------------------------------------------------------------------
req		            : Creates and processes certificate requests.
-x509		        : Using this argument we can produce a self signed certificate.
-nodes              : Means that the created private key will not be encrypted.
-days 365	        : Used along with -x509, means that our certificate is certified for 365 days. 
-newkey rsa:1024    : Creates a certificate request and a private key. rsa:1024 generates a RSA key of 1024 bits.
-keyout mycert.pem  : Filename where the new private key is written (In our case mycert.pem).
-out mycert.pem	    : The created certificate request file location (In our case mycert.pem).
--------------------------------------------------------------------------------------
