var intlData = {
    locales: "en-US",
    messages: {
        emptyValue: "-",
        goOutputFolder: "Go to output folder",
        viewLogs: "View logs",
        goOutputFolderOf: "Go to output folder of",
        viewParam: "View Parameters",
        relaunch: "Relaunch...",
        noAnalyses: "No analyses to display",
        ariaCheckbox: "{label} checkbox",
        analysisInfo: "View Analysis Info",
        gridView: "Grid View",
        tableView: "Table View",
        share: "Share with collaborators...",
        completeAndSave: "Complete and Save Outputs",
        cancel: "Cancel",
        ok: "Ok",
        delete: "Delete",
        rename: "Rename...",
        updateComments: "Update Comments...",
        analyses: "Analyses",
        refresh: "Refresh",
        analysisInfoTitle: "Analysis Info",
        okBtnText: "OK",
        cancelBtnText: "Cancel",
        comments: "Comments",
        analysisParamTitle: "Viewing parameters for {name}",
        renameDlgHeader: "Rename Analysis",
        renamePrompt: "Rename",
        commentsDlgHeader: "Comments",
        commentsPrompt: "Comments...",
        search: "Search...",
        analysis: "Analysis",
        analysisId: "Analysis ID",
        app: "App",
        currentStatus: "Current Status",
        outputFolder: "Output folder",
        startDate: "Start date",
        endDate: "End date",
        user: "User",
        name: "Name",
        email: "Email",
        submit: "Submit",
        noOutput: "Analysis completed but I got no output.",
        unExpectedOutput: "Analysis completed but I got unexpected output.",
        outputConditionHeader: "Select Output condition:",
        saveToFile: "Save to file",
        type: "App Type",
        viewFilter: "View",
        appTypeFilter: "App Type",
        viewingBatch: "Viewing Batch: {name}",
        needHelp: "I still need help!",
        noAnalysis: "No Analyses!",
        htDetails: "View HT Analyses details",
        viewAll: "View All Analyses",
        analysisInfoDlgTitle: "Analysis Info",
        copyAnalysisId: "Copy Analysis ID",
        followLogs: "Follow Logs",
        jobLogsUnavailableMessage:
            "The logs will be available within the analysis output folder after the status of this" +
            " analysis changes to Completed or Failed.",
        jobLogsUnavailableHeading: "Logs not available",
        goToVice: "Go to analysis",
        extendTime: "Extend time limit",
        extendTimeLimitMessage:
            "This analysis is scheduled to be terminated at {timeLimit}. Do you" +
            " wish" +
            " to extend the time limit?",
        analysesExecDeleteWarning:
            "This will remove the selected analyses and the parameters information associated with those analyses. Outputs can still be viewed in the Data window within the folder created by these analyses.",
        analysesMultiRelaunchWarning:
            "Relaunching more than one analysis at once will relaunch all selected analyses, reusing their original parameters and analysis names." +
            " If the selected analyses are sub-jobs of an HT analysis, then those selected analyses will still be nested under that parent HT analysis," +
            " and their output folders will also be grouped under that parent HT analysis' output folder," +
            " but the relaunched sub-jobs will be renamed with a `-redo-#` suffix to differentiate them from their original sub-jobs." +
            " Otherwise, relaunched analyses will be treated as new analyses, even though they reuse the same name and parameters as their original analyses.",
    },
};

export default intlData;
