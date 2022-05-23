# java-uuid

A replacement implementation for `java.util.UUID` with the missing RFC 4122 features.

## Features

 * All `java.util.UUID` features.
 * Generation of RFC 4122 type 1 (time based) UUID, with current and arbitrary time stamps.
 * Generation of RFC 4122 type 3 (MD5 based) UUID, with RFC 4122 pre-defined namespaces or custom namespaces.
 * Generation of RFC 4122 type 5 (SHA1 based) UUID, with RFC 4122 pre-defined namespaces or custom namespaces.
 * RFC 4122 compliance for reading, parsing and outputing the UUID data.
 * Output UUID data as a byte array ("raw format").

## Usage

Copy the source file in [`src/main/java/coil/geek/UUID.java`](./src/main/java/coil/geek/UUID.java)
to where you want to use it. Don't forget to change the `package` line according to the directory
you place the file into.

Use the class like you'd normally use `java.util.UUID`.

### Testing

The included JUnit 5 test case exercises all the major functionality of the API.

## More Information 

At this point I'm not planning to build an actual package for this small bit of code -
copy&paste it and do with it as you like (as long as you retain the copyright notices at the top
of the file).

Modifications suggestions are welcome, though do note that while I want this implementation to be
a complete RFC 4122 implementation, it should still be simple and not stray too far from the
`java.util.UUID` API.
