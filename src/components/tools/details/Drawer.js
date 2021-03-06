/**
 * @author sriram
 *
 * A drawer that display tabs with various information such as job history, params etc...
 *
 */

import React, { useState } from "react";

import { useQuery } from "react-query";
import { useTranslation } from "i18n";

import { build } from "@cyverse-de/ui-lib";

import ids from "../ids";
import constants from "../../../constants";
import DETabPanel from "../../utils/DETabPanel";
import ToolDetails from "./ToolDetails";
import TableView from "components/apps/listing/TableView";

import {
    getToolDetails,
    getAppsUsed,
    TOOL_DETAILS_QUERY_KEY,
    APPS_USING_QUERY_KEY,
} from "serviceFacades/tools";

import { Drawer, Tab, Tabs, Typography } from "@material-ui/core";
import { makeStyles } from "@material-ui/core/styles";

const TABS = {
    toolDetails: "TOOL DETAILS",
    appsUsingTool: "APPS USING TOOL",
};

const useStyles = makeStyles((theme) => ({
    drawerPaper: {
        [theme.breakpoints.up("lg")]: {
            maxWidth: "25%",
        },
        [theme.breakpoints.down("lg")]: {
            maxWidth: "50%",
        },
        [theme.breakpoints.down("sm")]: {
            maxWidth: "90%",
        },
    },

    drawerHeader: {
        margin: theme.spacing(1),
        display: "flex",
        flexDirection: "row",
        maxWidth: "100%",
    },
    drawerSubHeader: {
        marginLeft: theme.spacing(2),
        display: "flex",
        flexDirection: "row",
        maxWidth: "100%",
    },

    tabIndicator: {
        backgroundColor: theme.palette.secondary.main,
        color: theme.palette.secondary.contrastText,
    },
    tabSelected: {
        color: theme.palette.primary.contrastText,
        backgroundColor: theme.palette.primary.main,
    },
    headerOperations: {
        marginLeft: theme.spacing(1),
    },
}));

function DetailsDrawer(props) {
    const classes = useStyles();
    const { t } = useTranslation("tools");
    const { selectedTool, open, onClose, baseId } = props;
    const [selectedTab, setSelectedTab] = useState(TABS.toolDetails);
    const [details, setDetails] = useState();
    const [apps, setApps] = useState();

    const drawerId = build(baseId, ids.DETAILS_DRAWER);
    const infoTabId = build(drawerId, ids.INFO_TAB);
    const appsTabId = build(drawerId, ids.APPS_USING_TOOL);

    const { isFetching: isInfoFetching, error: infoFetchError } = useQuery({
        queryKey: [TOOL_DETAILS_QUERY_KEY, { id: selectedTool?.id }],
        queryFn: getToolDetails,
        config: {
            enabled: !!selectedTool,
            onSuccess: setDetails,
        },
    });

    const { isFetching: isAppsFetching, error: appsFetchError } = useQuery({
        queryKey: [APPS_USING_QUERY_KEY, { id: selectedTool?.id }],
        queryFn: getAppsUsed,
        config: {
            enabled: !!selectedTool,
            onSuccess: setApps,
        },
    });

    const onTabSelectionChange = (event, selectedTab) => {
        setSelectedTab(selectedTab);
    };

    if (!selectedTool) {
        return null;
    }

    const toolName = selectedTool.name;

    return (
        <Drawer
            onClose={onClose}
            open={open}
            anchor="right"
            PaperProps={{
                id: drawerId,
                classes: { root: classes.drawerPaper },
                variant: "outlined",
            }}
        >
            <div className={classes.drawerHeader}>
                <Typography variant="h6">{toolName}</Typography>
            </div>
            <Tabs
                value={selectedTab}
                onChange={onTabSelectionChange}
                classes={{ indicator: classes.tabIndicator }}
            >
                <Tab
                    value={TABS.toolDetails}
                    label={t("toolInformationLbl")}
                    id={infoTabId}
                    classes={{ selected: classes.tabSelected }}
                    aria-controls={build(infoTabId, ids.PANEL)}
                />
                <Tab
                    value={TABS.appsUsingTool}
                    label={t("appsUsingToolLbl")}
                    id={appsTabId}
                    classes={{ selected: classes.tabSelected }}
                    aria-controls={build(appsTabId, ids.PANEL)}
                />
            </Tabs>
            <DETabPanel
                tabId={infoTabId}
                value={TABS.toolDetails}
                selectedTab={selectedTab}
            >
                <ToolDetails
                    tool={details}
                    baseDebugId={infoTabId}
                    isInfoFetching={isInfoFetching}
                    infoFetchError={infoFetchError}
                />
            </DETabPanel>
            <DETabPanel
                tabId={appsTabId}
                value={TABS.appsUsingTool}
                selectedTab={selectedTab}
            >
                <TableView
                    loading={isAppsFetching}
                    baseId={appsTabId}
                    enableMenu={false}
                    enableSorting={false}
                    enableSelection={false}
                    enableDelete={false}
                    listing={apps}
                    error={appsFetchError}
                    selected={[]}
                    order={constants.SORT_ASCENDING}
                    orderBy="name"
                />
            </DETabPanel>
        </Drawer>
    );
}
export default DetailsDrawer;
