import java.io.File
import org.apache.tools.ant.taskdefs.condition.Os
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.logging.LogLevel
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.TaskAction

open class BuildTask : DefaultTask() {
    @Input
    var rootDirRel: String? = null

    @Input
    var target: String? = null

    @Input
    var release: Boolean? = null

    @TaskAction
    fun assemble() {
        // Use Cargo to run Tauri CLI: `cargo tauri android android-studio-script ...`
        val cargoExecutable = if (Os.isFamily(Os.FAMILY_WINDOWS)) "cargo.exe" else "cargo"
        runTauriCli(cargoExecutable)
    }

    private fun runTauriCli(cargoExecutable: String) {
        val rootDirRel = rootDirRel ?: throw GradleException("rootDirRel cannot be null")
        val target = target ?: throw GradleException("target cannot be null")
        val release = release ?: throw GradleException("release cannot be null")

        // Build args for cargo:
        // cargo tauri android android-studio-script --target <target> [--release] [-v|-vv]
        val args = mutableListOf(
          "tauri",
          "android",
          "build",
          "--target",
          target
        )

        if (release) {
            args.add("--release")
        }

        // Logging verbosity
        if (project.logger.isEnabled(LogLevel.DEBUG)) {
            args.add("-vv")
        } else if (project.logger.isEnabled(LogLevel.INFO)) {
            args.add("-v")
        }

        project.exec {
            workingDir(File(project.projectDir, rootDirRel))
            executable(cargoExecutable)
            args(args)
        }.assertNormalExitValue()
    }
}