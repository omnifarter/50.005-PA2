How to run the code:

1. cd to the desired protocol's (CP1 or CP2) client and server (1 terminal each).
2. compile the client and server using "javac ClientWithSecurityCPx.java" and "javac ServerWithSecurityCPx.java" respectively, where you replace CPx with either CP1 or CP2.
3. run the server first, using "java  ServerWithSecurityCPx".
4. make sure whatever you would like to transfer is directly inside the client's root folder (../CPx/Client).
5. after the server is running, run the client using "java ClientWithSecurityCPx args" where args are your filenames that you would like to transfer. You can input more than 1 filename, to be seperated with a space.
6. after the program is complete, you will now have the transferred files, with name recv_filename inside the server's root folder (../CPx/Server).