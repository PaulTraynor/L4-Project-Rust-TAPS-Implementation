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
* *1 hour* Investing whether Tokio and Mio can interoperate 

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