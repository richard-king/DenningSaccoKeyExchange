Goals
• Implement the Denning-Sacco[?] Protocol.
• This will require you to write a Java client (acting for A) and two Java servers (acting for B and S).
– The servers should be able to accept multiple sequential and concurrent connections.
The Application
• The application consists of 3 command-line programs.
– A server program that will authenticate users and issue session keys.
– A client A program that allows a user to type a line of text that is sent to a client B program.
– The client B program reverses the line and send it back to A.
– The data transferred between client A and client B is encrypted with the session key obtained
using the Denning-Sacco protocol.
The Protocol
1. A → S : A, B
2. S → A : {T, B, k<A,B>, {T, A, k<A,B>}k<B,S>}k<A,S>
3. A → B : {T, A, k<A,B>}k<B,S>
4. A → B : {M1}k<A,B>
5. B → A : {M2}k<A,B>
where M1 and M2 are strings such that M2 is the reverse of M1 .

Java
• You need to write three command-line programs:
1. Server.java
– This program implements the Denning-Sacco server S.
2. ClientA.java
– This program implements entity A.
3. ClientB.java
– This program implements entity B.
• Your source code should be submitted as a single-level JAR file ds.jar with no embedded directories.
The file ds.jar will be placed in a directory project and the following commands will be used to
compile your programs using Java 1.6:
cd project
jar xvf ds.jar
javac *.java
• All your programs will be executed form command-line windows from within the directory project.
Port Numbers & Timestamp Delta
• The programs may be run on the same or different computers.
• Server accepts connections from ClientB. The port number on which Server waits is supplied as a
command-line argument:
java Server <port S>
• ClientA makes connections to the Server and ClientB. This requires the following command-line
arguments:
java ClientA <IP B> <port B> <IP S> <port S> [delta]
where delta is an optional argument that specifies the timestamp delta to be used by ClientA. The
default is 60 seconds.
• ClientB requires the port number on which it will wait:
java ClientB <port B>
[delta]
• When testing your software I will use three command-line windows and I will start your programs in
these windows in the following order:
Window One:
java Server
6000
Window Two:
java ClientB 5000

Window Three:
java ClientA 127.0.0.1 5000 127.0.0.1 6000
• I may use the port numbers specified above or I may use different port numbers.
• I may run the programs on the same or different computers.
• I may supply timestamp delta values.
Deliverables
1. All the source code and any other files needed to compile and run your project.
Project Submission
• You are required to submit your source code as a single-level JAR file ds.jar with no embedded
directories.
• Submission will be via the web site.
Terms & Conditions
• The project must be done individually and not in groups. Any copying or collaboration will result in
you failing the module.
• Your programs should only use standard Java input and output commands and not a GUI.
• You programs should use exactly the command-line arguments described above.
• To mark your project, I will inspect your code and test your software.
– It is very important that you write well structured, readable code.
Notes
• Your programs should use the following strings:
– “Student” for A
– “Lecturer” for B
• You should use AES keys.
• The keys k A,S and k
implementation.
B,S
can be obtained by executing the program showds; see the reference
• Encryption uses AES in CBC mode with PKCS#5 padding.
• You should use Type-Value-Length (TVL) encodings.
• There are two test servers:
1. Server : 136.206.11.108:8014
2. ClientB : 136.206.11.108:8015

