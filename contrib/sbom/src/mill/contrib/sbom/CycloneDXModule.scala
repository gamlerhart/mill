package mill.contrib.sbom

import coursier.core as cs
import coursier.params.ResolutionParams
import mill.*
import mill.contrib.sbom.CycloneDXModule.Component
import mill.define.Command
import mill.javalib.{BoundDep, JavaModule}
import mill.util.Jvm.ResolvedDependency
import os.Path
import upickle.default.{ReadWriter, macroRW}

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import java.util.{Base64, UUID}

object CycloneDXModule {
  case class SBOM_JSON(
      bomFormat: String,
      specVersion: String,
      serialNumber: String,
      version: Int,
      metadata: MetaData,
      components: Seq[Component]
  )
  case class MetaData(timestamp: String = Instant.now().toString)
  case class ComponentHash(alg: String, content: String)
  case class LicenseHolder(license:License)
  case class License(name: String, url:Option[String])
  case class Component(
      `type`: String,
      `bom-ref`: String,
      group: String,
      name: String,
      version: String,
      description: String,
      licenses: Seq[LicenseHolder],
      hashes: Seq[ComponentHash]
  )
  object Component {
    def fromDeps(dependency: ResolvedDependency): Component = {
      val dep = dependency.dependency
      val licenses = dependency.licenses.map{lic =>
        LicenseHolder(License(lic.name, lic.url))
      }
      Component(
        "library",
        s"pkg:maven/${dep.module.organization.value}/${dep.module.name.value}@${dep.version}?type=jar",
        dep.module.organization.value,
        dep.module.name.value,
        dep.version,
        dep.module.orgName,
        licenses,
        Seq(ComponentHash("SHA-256", sha256(dependency.path.path)))
      )
    }
  }

  implicit val sbomRW: ReadWriter[SBOM_JSON] = macroRW
  implicit val metaRW: ReadWriter[MetaData] = macroRW
  implicit val componentHashRW: ReadWriter[ComponentHash] = macroRW
  implicit val componentRW: ReadWriter[Component] = macroRW
  implicit val licenceHolderRW: ReadWriter[LicenseHolder] = macroRW
  implicit val licenceRW: ReadWriter[License] = macroRW


  private def sha256(f: Path): String = {
    val md = MessageDigest.getInstance("SHA-256")
    val fileContent = os.read.bytes(f)
    val digest = md.digest(fileContent)
    String.format("%0" + (digest.length << 1) + "x", new BigInteger(1, digest))
  }
  case class SbomHeader(serialNumber:UUID, timestamp:Instant)
}

trait CycloneDXJavaModule extends JavaModule with CycloneDXModule{
  /** Lists of all components used for this module.
   * By default, uses the [[ivyDeps]] and [[runIvyDeps]] for the list of components */
  def sbomComponents: Task[Agg[Component]] = Task {
    resolvedRunIvyDepsDetails()().map(Component.fromDeps)
  }

  /** Copied from [[resolvedRunIvyDeps]] */
  private def resolvedRunIvyDepsDetails(): Task[Seq[ResolvedDependency]] = Task.Anon {
    millResolver().resolveDepsExtendInfo(
      Seq(
        BoundDep(
          coursierDependency.withConfiguration(cs.Configuration.runtime),
          force = false
        )
      ),
      artifactTypes = Some(artifactTypes()),
      resolutionParamsMapOpt =
        Some((_: ResolutionParams).withDefaultConfiguration(cs.Configuration.runtime))
    )
  }
}

trait CycloneDXModule extends Module {
  import CycloneDXModule.*

  /** Lists of all components used for this module. */
  def sbomComponents: Task[Agg[Component]]

  /** Each time the SBOM is generated, a new UUID and timestamp are generated
   * Can be overridden to use a more predictable method, eg. for reproducible builds */
  def sbomHeader(): SbomHeader = SbomHeader(UUID.randomUUID(), Instant.now())

  /**
   * Generates the SBOM Json for this module, based on the components returned by [[sbomComponents]]
   * @return
   */
  def sbom: T[SBOM_JSON] = Target {
    val header = sbomHeader()
    val components = sbomComponents()

    SBOM_JSON(
      bomFormat = "CycloneDX",
      specVersion = "1.2",
      serialNumber = s"urn:uuid:${header.serialNumber}",
      version = 1,
      metadata = MetaData(timestamp = header.timestamp.toString),
      components = components
    )
  }

  def sbomJsonFile: T[PathRef] = Target {
    val sbomFile = Target.dest / "sbom.json"
    os.write(sbomFile, upickle.default.write(sbom(),indent = 2))
    PathRef(sbomFile)
  }



}
