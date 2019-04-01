## Dev Environment setup

1. Clone the repo
2. Run `./gradlew localizer`

Install:

- Eclipse 2018-12 Java EE
- import this project as an "existing project"

## Running locally

To run a local development server of Jenkins for testing run

```sh
# serves at at http://localhost:8080/
./gradlew server
```

To build the plugin locally run

```sh
./gradlew jpi
```

## Updating Strings

Make updates as needed in `Messages.properties` and then run

```sh
./gradlew localizer
```

## Editing `*.jelly` files

1. In Eclipse open Window > Preferences
2. Under Content Types expand Text > JSP
3. Select JSP and click "Add..." beside File associations
4. Enter `*.jelly`
5. Apply and Close
6. Right click on a `*.jelly` file and choose Open With > Other...
7. Select JSP Editor and check "Use for all '\*.jelly' files"

## Releasing

Follow the Jenkins documentation for
[making a new release](https://wiki.jenkins.io/display/JENKINS/Hosting+Plugins).
