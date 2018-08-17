# Boiler Plate Attester Web Flow #

This Maven project serve as a boiler plate Spring Web Flow for
attesters to issue attestations.

## Play around ##

Check if your development environment have equal or better tools than
the environment this project was developed in:

	$ java -version
	java version "1.8.0_171"
	$ mvn -version
	Apache Maven 3.3.9

Then run the project:

    $ mvn tomcat7:run
	
When the command reaches the following output the web service is accessbile:

    INFORMATION: Starting ProtocolHandler ["http-bio-8080"]

It is accessible at http://localhost:8080/activationFlow

## If you don't have Java 10 ##

It should work with lower java versions. Just play around with
`maven.compiler.source` and `maven.compiler.target` properties in
`pom.xml`.
