package com.codeshield.intellij.ui

import com.codeshield.intellij.backend.BackendClient
import com.codeshield.intellij.backend.Finding
import com.intellij.ide.util.PropertiesComponent
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.fileEditor.FileDocumentManager
import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.fileEditor.OpenFileDescriptor
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.vfs.VirtualFile
import java.awt.BorderLayout
import java.awt.FlowLayout
import javax.swing.DefaultListCellRenderer
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.ListSelectionModel

private const val BACKEND_URL_KEY = "codeshield.ide.backendUrl"
private const val DEFAULT_BACKEND_URL = "http://127.0.0.1:8000"

class CodeShieldPanel(private val project: Project) : JPanel(BorderLayout()) {
    private val status = JLabel("Ready. Scan the active Python or JavaScript file.")
    private val model = DefaultListModel<Finding>()
    private val findings = JList(model)

    init {
        val toolbar = JPanel(FlowLayout(FlowLayout.LEFT))
        val scanButton = JButton("Scan Active File")
        val backendButton = JButton("Backend URL…")
        toolbar.add(scanButton)
        toolbar.add(backendButton)

        findings.selectionMode = ListSelectionModel.SINGLE_SELECTION
        findings.cellRenderer = DefaultListCellRenderer()
        findings.addListSelectionListener { event ->
            if (!event.valueIsAdjusting) findings.selectedValue?.let(::navigateToFinding)
        }

        scanButton.addActionListener { scanActiveFile() }
        backendButton.addActionListener { configureBackend() }

        add(toolbar, BorderLayout.NORTH)
        add(JScrollPane(findings), BorderLayout.CENTER)
        add(status, BorderLayout.SOUTH)
    }

    private fun scanActiveFile() {
        val file = FileEditorManager.getInstance(project).selectedFiles.firstOrNull()
        if (file == null) {
            status.text = "Open a Python or JavaScript file first."
            return
        }
        val language = languageFor(file)
        if (language == null) {
            status.text = "Only .py, .js, .jsx, .mjs, and .cjs files are supported."
            return
        }
        val document = FileDocumentManager.getInstance().getDocument(file)
        if (document == null) {
            status.text = "Could not read the active editor document."
            return
        }

        val source = document.text
        val backendUrl = currentBackendUrl()
        status.text = "Scanning ${file.name}…"
        object : Task.Backgroundable(project, "CodeShield: scanning ${file.name}", true) {
            override fun run(indicator: ProgressIndicator) {
                indicator.isIndeterminate = true
                try {
                    val results = BackendClient(backendUrl).scan(language, file.name, source)
                        .map { it.copy(file = file) }
                    ApplicationManager.getApplication().invokeLater {
                        if (project.isDisposed) return@invokeLater
                        model.clear()
                        results.forEach(model::addElement)
                        status.text = if (results.isEmpty()) {
                            "No findings in ${file.name}."
                        } else {
                            "${results.size} finding(s) in ${file.name}. Select one to jump to its line."
                        }
                    }
                } catch (error: Exception) {
                    ApplicationManager.getApplication().invokeLater {
                        if (project.isDisposed) return@invokeLater
                        status.text = "Scan failed: ${error.message ?: error.javaClass.simpleName}"
                    }
                }
            }
        }.queue()
    }

    private fun configureBackend() {
        val properties = PropertiesComponent.getInstance()
        val current = properties.getValue(BACKEND_URL_KEY, DEFAULT_BACKEND_URL)
        val entered = Messages.showInputDialog(
            project,
            "CodeShield backend URL (the backend should listen on loopback):",
            "CodeShield Backend",
            Messages.getQuestionIcon(),
            current,
            null,
        ) ?: return

        try {
            val normalized = BackendClient.validateLoopbackBase(entered)
            properties.setValue(BACKEND_URL_KEY, normalized)
            status.text = "Backend URL set to $normalized"
        } catch (error: IllegalArgumentException) {
            Messages.showErrorDialog(project, error.message ?: "Invalid backend URL", "Invalid CodeShield Backend URL")
        }
    }

    private fun currentBackendUrl(): String = PropertiesComponent.getInstance()
        .getValue(BACKEND_URL_KEY, DEFAULT_BACKEND_URL)

    private fun navigateToFinding(finding: Finding) {
        OpenFileDescriptor(
            project,
            finding.file ?: return,
            (finding.line - 1).coerceAtLeast(0),
            (finding.column - 1).coerceAtLeast(0),
        ).navigate(true)
    }

    private fun languageFor(file: VirtualFile): String? = when (file.extension?.lowercase()) {
        "py" -> "python"
        "js", "jsx", "mjs", "cjs" -> "javascript"
        else -> null
    }
}
