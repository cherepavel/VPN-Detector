package com.cherepavel.vpndetector.ui.export

data class ExportReport(
    val title: String,
    val generatedAt: String,
    val buildInfo: String,
    val sourceCodeUrl: String,
    val sections: List<ExportSection>
)

data class ExportSection(
    val title: String,
    val items: List<ExportItem>
)

sealed class ExportItem {
    data class Field(
        val label: String,
        val value: String
    ) : ExportItem()

    data class ListBlock(
        val label: String,
        val values: List<String>
    ) : ExportItem()

    data class Paragraph(
        val text: String
    ) : ExportItem()
}
