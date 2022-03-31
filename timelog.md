# Timelog

* Implementing The Transport Services API in Rust
* Paul Christopher Traynor
* 2205382t
* Supervisor: Colin Perkins

## Guidance

* This file contains the time log for your project. It will be submitted along with your final dissertation.
* **YOU MUST KEEP THIS UP TO DATE AND UNDER VERSION CONTROL.**
* This timelog should be filled out honestly, regularly (daily) and accurately. It is for *your* benefit.
* Follow the structure provided, grouping time by weeks.  Quantise time to the half hour.

## Week 1

### 30 Sep 2021

* *2 hours* Read the draft-ietf-taps-impl-10 document 
* *0.5 hour* Started new Rust project and created GitHub Repository 
* *0.5 hour* Created dissertation repo and added space for minutes   
* *0.5 hour* meeting with supervisor

## Week 2

### 03 Oct 2021

* *0.5 hour* Starting working on requirements for the project and a plan 

### 04 Oct 2021

* *1 hour* Finished requirements analysis and plan, emailed to supervisor
* *1 hour* Started reading example dissertation
 
### 05 Oct 2021

* *1 hour* Finished reading example dissertation

### 06 Oct 2021

* *0.5 hour* Meeting with supervisor
* *3 hours* Reading and experimenting with quiche (Rust QU|IC implementation)

### 08 Oct 2021

* *4 hours* Further experimentation with quiche

### 10 Oct 2021

* *3 hours* Writing up formal requirements document 

## Week 3

### 11 Oct 2021

* *1 hour* Finished writing up formal requirements document 

## Week 4

### 18 Oct 2021

* *3 hours* Writing requirements in MOSCOW format, making a diagram to show the API design and writing up a timeline for the project

### 19 Oct 2021

* *1 hour* Finished timeline, emailed all three documents to supervisor

### 20 Oct 2021

* *0.5 hour* Meeting with supervisor

### 22 Oct 2021

* *2 hours* Began coding, started implementation of basic structs and traits

### 24 Oct 2021 

* *2 hours* Began implementation of transport properties

## Week 5

### 25 Oct 2021 

* *1 hour* Began implementation of security properties and Messages

### 26 Oct 2021

* *2 hours* Wrote up API design specification

### 27 Oct 2021

* *0.5 hour* Meeting with supervisor

### 28 Oct 2021

* *1 hour* Implementing and testing dns code
* *2 hours* Reading up on concurrency and OOP features in Rust

### 29 Oct 2021

* *1 hour* Further reading of OOP features in Rust

### 30 Oct 2021

* *4 hours* Changing Connection to struct, modifying Preconnection to return Connection and adding TCP code for send, receive and close actions

## Week 6

### 01 Nov 2021

* *0.5 hour* Improving existing API design specification
* *1 hour* Adding rest of tcp-specific code

### 02 Nov 2021

* *3 hours* Experimenting with different designs and implementations for messages, message parsing and framers

### 03 Nov 2021

* *0.5 hours* Meeting with supervisor
* *1 hour* Adding Framer trait and coding an implementation as an example
* *0.5 hours* Researching async/await in Rust

### 05 Nov 2021

* *2 hours* Researching Nom

### 06 Nov 2021

* *1 hour* Researching Tokio
* *0.5 hours* Trying and modifying examples of asynchronous networking code in Python

## Week 7

### 08 Nov 2021

* *2 hours* Researching Tokio

### 09 Nov 2021

* *2 hours* Examining Quiche code examples and figuring out they worked
* *3 hours* Researching  and experimenting with Tokio

### 10 Nov 2021

* *4 hours* Added code to create QUIC connections, and send and receive data using QUIC

### 12 Nov 2021

* *4 hours* Coded TCP and QUIC listeners and related methods 

## Week 8

### 15 Nov 2021

* *3 hours* Started an example HTTP parser using nom

### 20 Nov 2021

* *3 hours* Started implementing TLS over TCP code using rustls

### 21 Nov 2021

* *4 hours* Finished implementation of Connections using rustls

## Week 9

### 23 Nov 2021

* *4 hours* Coding TLS over TCP listener 

### 24 Nov 2021

* *0.5 hours* Meeting with supervisor 
* *1 hour* Investigating whether Tokio and Mio can interoperate 

### 26 Nov 2021

* *2 hours* Started reimplementing TLS over TCP using tokio-rustls
* *1 hour* Made existing QUIC connect method asynchronous using Tokio

### 27 Nov 2021

* *2 hours* Converted all existing send, receive and close methods to be asynchronous 
* *1 hours* Converted existing listener methods to be asynchronous 

### 28 Nov 2021

* *2 hours* Completed implementation of TLS over TCP using tokio-rustls

## Week 10

### 29 Nov 2021

* *0.5 hours* Modified QUIC receive method to check all readable streams 
* *2 hours* Researching and experimenting with external HTTP libraries to be used for framing HTTP requests and responses 
* *1 hour* Added selection properties from TAPS and relevant security parameters 

### 30 Nov 2021

* *2 hours* Started candidate gathering 
* *1 hour* Public API improvements

### 01 Dec 2021

* *0.5 hours* Meeting with supervisor
* *2 hours* Added ordering of candidates, finished candidate gathering 
* *1.5 hour* Stopped using split for TLS/TCP connections, using other methods instead for send/recv

### 03 Dec 2021

* *3 hours* Started re-implementation of QUIC using quinn 

### 05 Dec 2021

* *1 hour* Started default HTTP framer
* *2 hours* Started connection racing 
* *1.5 hours* Extended QUIC code to include accept connections on a listener

## Week 11

### 06 Dec 2021

* *2.5 hours* Fully implemented connection racing for TCP

### 07 Dec 2021

* *3 hours* Implemented connection racing for TLS/TCP and QUIC

### 11 Dec 2021

* *2 hours* TCP connection racing tested successfully 
* *1 hour* Modified async code to increase interleaving of tasks

### 12 Dec 2021

* *2.5 hours* Implemented outer Listener struct- experimented with various design options 
* *2 hours* Returning stream of protocol listeners - implemented Stream trait on all protocols

## Week 12

### 13 Dec 2021

* *3 hours* Added listener racing for all protocols 
* *2.5 hours* Debugging asynchronous code for TLS/TCP listener racing 
* *2.5 hours*  Reading up on HTTP headers and their meanings, as well as difference between versions 

### 14 Dec 2021

* *5 hours* Coded framer for HTTP requests 
* *3 hours* Coded framer for HTTP responses 

### 15 Dec 2021

* *0.5 hours* Meeting with supervisor
* *3 hours* Tested and debugged HTTP framer
* *2 hours* Designing what the re-implementation of connections and listeners as traits would look like

## 27/12 - 02/01

### 27 Dec 2021

* *6 hours* Re-implemented connections as traits and return an implementation of this from initiate() method

### 28 Dec 2021

* *3 hours* Testing send() and receive() methods on TLS/TCP
* *4 hours* Re-implemented listeners as traits 

## Week 13

### 12 Jan 2022

* *0.5 hours* Meeting with supervisor

### 16 Jan 2022

* *2.5 hours* Fixed problems with QUIC cryptographic handshake 

## Week 14

### 18 Jan 2022

* *1.5 hours* Debugging QUIC listener

### 19 Jan 2022

* *0.5 hours* Meeting with supervisor

### 22 Jan 2022

* *3 hours* modified QUIC listener to use OS certificates if none specified 

### 23 Jan 2022

* *4 hours* Attempting to separate the concepts of messages and framers and fit them into connection, pre_connection etc.

## Week 15

### 24 Jan 2022

* *5 hours* Trying out implementing different message and framer integrations into the codebase

### 26 Jan 2022

* *0.5 hours* Meeting with supervisor

### 30 Jan 2022

* *1.5 hours* Improved interface by adding a default method for transport properties and setters for security parameters
* *1 hour* Created message struct
* *1.5 hours* Modified all send and recv methods to use messages

## Week 16 

### 31 Jan 2022

* *2 hours* Modified all protocol send and recv methods to return Result enums, making the API more event driven

### 01 Feb 2022

* *1.5 hours* Increased robustness of TLS/TCP code by matching on more error prone parts of the code
* *1 hour* Modified initiate and listen methods to return Result enums

### 02 Feb 2022

* *0.5 hours* Meeting with supervisor

### 05 Feb 2022

* *2.5 hours* Started dissertation Design chapter

### 06 Feb 2022

* *3 hours* Finished 1st draft design chapter and added figures

## Week 17

### 07 Feb 2022

* *2 hours* Started testing

### 12 Feb 2022

* *4 hours* Started modifying design chapter to include more discussion on decisions and trade-offs

### 13 Feb 2022

* *2 hours* Finished latest draft of design chapter

## Week 18

### 19 Feb 2022

* *3 hours* Extended design chapter to include overview 

### 20 Feb 2022

* *2.5 hours* Completed first draft of background chapter

## Week 19

### 21 Feb 2022

* *4 hours* Started introduction chapter

### 26 Feb 2022

* *4.5 hours* Changed Design/Implementation chapters to Implementation/Internals, wrote internals  

### 27 Feb 2022

* *2 hours* Further extended Internals chapter

## Week 20

### 28 Feb 2022 

* *2.5 hours* Started Evaluation chapter

### 01 Mar 2022

* *1 hour* Transitioned to library crate

### 02 Mar 2022

* *5 hours* Mininet testing for Candidate Racing 

### 03 Mar 2022

* *3 hours* Extended Background chapter further
* *1 hour* Added example API use section to API chapter

### 04 Mar 2022

* *2 hours* Code cleanup and Message extensions

### 05 Mar 2022

* *2.5 hours* Added comparison with sockets to Evaluation 

### 06 Mar 2022

* *1.5 hours* Started comparison with rs-TAPS in dissertation

## Week 21

### 07 Mar 2022 

* *4 hours* Mininet testing for Framer errors

### 08 Mar 2022

* *1 hour* Extended Background further to discuss Apple Network.framework

### 09 Mar 202

* *1.5 hours* Added discussion of QUIC and HTTP/3 to API
* *1 hour* Added discussion of security parameters to API chapter

### 11 Mar 2022

* *4.5 hours* Modified Candidate Racing to use message passing

### 12 Mar 2022

* *2 hours* First draft conclusion 

### 13 Mar 2022

* *3 hours* Reimplementation of Messages as traits pt1

## Week 22

### 14 Mar 2022

* *3 hours* Reimplementation of Messages as traits pt2

## Week 23

### 21 Mar 2022

* *3.5 hours* Experimenting with alternatives for Send and Sync traits on Message trait

### 22 Mar 2022

* *2.5 hours* Modified dissertation API, Evaluation and Conclusion chapters to include discussion on new implementation of Messages 

### 26 Mar 2022

* *2 hours* Improved Background chapter by adding more context
* *1.5 hours* Extended conclusion by adding more reflection

### 27 Mar 2022

* *3 hours* General improvements to dissertation, grammar etc.
* *1 hour* Added discussion on the use of Box<T> syntax

## Week 24

### 28 Mar 2022

* *2.5 hours* Removed use of boxes for Messages
* *0.5 hours* Modified dissertation to reflect the above change
* *2 hours* Started presentation

### 29 Mar 2022

* *2 hours* General improvements to Messages- more convenient constructors for default types

### 30 Mar 2022

* *1.5 hours* Completed presentation slides
* *1 hour* Modified Evaluation chapter to reflect the focus of the chapter, the usability comparisons with sockets and rs-TAPS
* *1 hour* Replaced API diagram with an easier to read version

### 31 Mar 2022

* *2 hours* Recorded video presentation 
* *3.5 hours* Checked whole dissertation for mistakes and made improvements where necessary
