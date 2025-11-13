ThisBuild / version := "1.0.0"

ThisBuild / scalaVersion := "3.3.7"

libraryDependencies += "org.scalatest" %% "scalatest" % "3.2.19" % "test"

lazy val root = (project in file("."))
  .settings(
    name := "jipcs"
  )
