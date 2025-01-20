package mill.contrib.sbom

import mill.Agg
import mill.javalib._
import mill.testkit.TestBaseModule
import utest.{TestSuite, Tests, test}
object CyclonDXModuleTests extends TestSuite{
  object TestModule extends TestBaseModule {
    case object versionFile extends JavaModule with CycloneDXModule{
      def ivyDeps = Agg(
        ivy"org.testng:testng:6.11"
      )
    }
  }


  override def tests = Tests{
    test("hello world"){
      assert(false)
    }
  }
}
