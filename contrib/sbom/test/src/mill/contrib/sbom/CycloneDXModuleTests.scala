package mill.contrib.sbom

import mill.*
import mill.Agg
import mill.javalib.*
import mill.testkit.{TestBaseModule, UnitTester}
import utest.{TestSuite, Tests, test}
import mill.define.{Discover, Target}

import java.util.UUID
import java.time.Instant

object TestModule extends TestBaseModule {

  val fixedHeader = CycloneDXModule.SbomHeader(UUID.fromString("a9d6a1c7-18d4-4901-891c-cbcc8f2c5241"), Instant.parse("2025-03-17T17:00:56.263933698Z"))

  object noDeps extends JavaModule with CycloneDXJavaModule {}

  object withDeps extends JavaModule with CycloneDXJavaModule {
    override def sbomHeader(): CycloneDXModule.SbomHeader = fixedHeader
    override def ivyDeps = Agg(ivy"ch.qos.logback:logback-classic:1.5.12")
  }

  object withModuleDeps extends JavaModule with CycloneDXJavaModule {
    override def sbomHeader(): CycloneDXModule.SbomHeader = fixedHeader
    override def moduleDeps = Seq(withDeps)
    override def ivyDeps = Agg(ivy"commons-io:commons-io:2.18.0")
  }

  lazy val millDiscover = Discover[this.type]
}
object CycloneDXModuleTests extends TestSuite {

  override def tests = Tests {
    test("Report dependencies of an module without dependencies") - UnitTester(
      TestModule,
      null
    ).scoped { eval =>
      val Right(result) = eval.apply(TestModule.noDeps.sbom)
      val components = result.value.components
      assert(components.size == 0)
    }
    test("Report dependencies of a single module") - UnitTester(TestModule, null).scoped { eval =>
      val toTest = TestModule.withDeps
      val Right(result) = eval.apply(toTest.sbom)
      val Right(file) = eval.apply(toTest.sbomJsonFile)
      val components = result.value.components
      assert(components.size == 3)
      assert(components.exists(_.name == "logback-classic"))
      assert(components.exists(_.name == "logback-core"))
      assert(components.exists(_.name == "slf4j-api"))

      assertSameAsReference("withDeps.sbom.json", file.value)
    }
    test("Report transitive module dependenties") - UnitTester(TestModule, null).scoped { eval =>
      val toTest = TestModule.withModuleDeps
      val Right(result) = eval.apply(toTest.sbom)
      val Right(file) = eval.apply(toTest.sbomJsonFile)
      val components = result.value.components
      assert(components.size == 4)
      assert(components.exists(_.name == "commons-io"))
      assert(components.exists(_.name == "logback-classic"))
      assert(components.exists(_.name == "logback-core"))
      assert(components.exists(_.name == "slf4j-api"))

      assertSameAsReference("withModuleDeps.sbom.json", file.value)
    }
  }

  private def assertSameAsReference(refFile:String, file:PathRef) = {
    val reference = String(getClass.getClassLoader.getResourceAsStream(refFile).readAllBytes())
    val current = os.read(file.path)
    val actualContentPath = os.pwd / refFile
    if(reference!=current){
      os.write(actualContentPath, current)
    }
    assert(reference == current, s"The reference file and the current generated SBOM file should match. " +
      s"Reference $refFile. Actual file content at: $actualContentPath")
  }
}
