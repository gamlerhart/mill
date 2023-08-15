package mill.bsp.worker

import ch.epfl.scala.bsp4j.{BuildClient, BuildTargetIdentifier, StatusCode, TaskId}
import mill.api.{CompileProblemReporter, PathRef}
import mill.api.Result.{Skipped, Success}
import mill.eval.Evaluator
import mill.scalalib.JavaModule
import mill.scalalib.bsp.BspModule

private object Utils {

  def sanitizeUri(uri: String): String =
    if (uri.endsWith("/")) sanitizeUri(uri.substring(0, uri.length - 1)) else uri

  def sanitizeUri(uri: os.Path): String = sanitizeUri(uri.toNIO.toUri.toString)

  def sanitizeUri(uri: PathRef): String = sanitizeUri(uri.path)

  // define the function that spawns compilation reporter for each module based on the
  // module's hash code TODO: find something more reliable than the hash code
  def getBspLoggedReporterPool(
      originId: String,
      bspIdsByModule: Map[BspModule, BuildTargetIdentifier],
      client: BuildClient
  ): Int => Option[CompileProblemReporter] = { moduleHashCode: Int =>
    bspIdsByModule.find(_._1.hashCode == moduleHashCode).map {
      case (module: JavaModule, targetId) =>
        val buildTarget = module.bspBuildTarget
        val taskId = new TaskId(module.compile.hashCode.toString)
        new BspCompileProblemReporter(
          client,
          targetId,
          buildTarget.displayName.getOrElse(targetId.getUri),
          taskId,
          Option(originId)
        )
    }
  }

  // Get the execution status code given the results from Evaluator.evaluate
  def getStatusCode(resultsLists: Seq[Evaluator.Results]): StatusCode = {
    val statusCodes =
      resultsLists.flatMap(r => r.results.keys.map(task => getStatusCodePerTask(r, task)).toSeq)
    if (statusCodes.contains(StatusCode.ERROR)) StatusCode.ERROR
    else if (statusCodes.contains(StatusCode.CANCELLED)) StatusCode.CANCELLED
    else StatusCode.OK
  }

  private[this] def getStatusCodePerTask(
      results: Evaluator.Results,
      task: mill.define.Task[_]
  ): StatusCode = {
    results.results(task).result match {
      case Success(_) => StatusCode.OK
      case Skipped => StatusCode.CANCELLED
      case _ => StatusCode.ERROR
    }
  }

}
