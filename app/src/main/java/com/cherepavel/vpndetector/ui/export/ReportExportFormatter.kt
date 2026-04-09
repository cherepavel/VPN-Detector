package com.cherepavel.vpndetector.ui.export

object ReportExportFormatter {

    fun buildText(report: ExportReport): String {
        return buildString {
            appendLine(report.title)
            appendLine("Generated: ${report.generatedAt}")
            appendLine("Build: ${report.buildInfo}")
            appendLine("Source code: ${report.sourceCodeUrl}")
            appendLine()

            report.sections.forEachIndexed { index, section ->
                appendLine("=== ${section.title} ===")

                section.items.forEach { item ->
                    when (item) {
                        is ExportItem.Field -> {
                            appendLine("${item.label}: ${item.value}")
                        }

                        is ExportItem.ListBlock -> {
                            appendLine("${item.label}:")
                            item.values.forEach { value ->
                                appendLine("  $value")
                            }
                        }

                        is ExportItem.Paragraph -> {
                            appendLine(item.text)
                        }
                    }
                }

                if (index != report.sections.lastIndex) {
                    appendLine()
                }
            }
        }.trim()
    }
}
