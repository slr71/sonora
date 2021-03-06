/**
 *
 * Row level actions for analysis
 *
 * @author sriram
 *
 **/
import React from "react";
import { useTranslation } from "i18n";
import Link from "next/link";
import ids from "../ids";
import { build } from "@cyverse-de/ui-lib";

import {
    isInteractive,
    allowAnalysisTimeExtn,
    isBatchAnalysis,
    useRelaunchLink,
    useGotoOutputFolderLink,
} from "../utils";

import { IconButton } from "@material-ui/core";
import {
    HourglassEmptyRounded as HourGlass,
    Launch as LaunchIcon,
    PermMedia as OutputFolderIcon,
    Repeat as RelaunchIcon,
    UnfoldMore as UnfoldMoreIcon,
    Info,
} from "@material-ui/icons";

const RelaunchButton = React.forwardRef((props, ref) => {
    const { baseId, className, onClick, href } = props;
    const { t } = useTranslation("analyses");
    return (
        <IconButton
            size="small"
            id={build(baseId, ids.ICONS.RELAUNCH, ids.BUTTON)}
            className={className}
            href={href}
            onClick={onClick}
            ref={ref}
            color="primary"
            title={t("relaunch")}
        >
            <RelaunchIcon fontSize="small" />
        </IconButton>
    );
});

const GotoOutputFolderButton = React.forwardRef((props, ref) => {
    const { baseId, className, onClick, href } = props;
    const { t } = useTranslation("analyses");
    return (
        <IconButton
            size="small"
            id={build(baseId, ids.ICONS.OUTPUT, ids.BUTTON)}
            className={className}
            href={href}
            onClick={onClick}
            ref={ref}
            color="primary"
            title={t("goOutputFolder")}
        >
            <OutputFolderIcon fontSize="small" />
        </IconButton>
    );
});

export default function Actions(props) {
    const { t } = useTranslation("analyses");
    const {
        analysis,
        allowBatchDrillDown = true,
        handleDetailsClick,
        handleInteractiveUrlClick,
        handleBatchIconClick,
        baseId,
        username,
    } = props;

    const interactiveUrls = analysis.interactive_urls;
    const isDisabled = analysis.app_disabled;

    const isBatch = isBatchAnalysis(analysis);
    const isVICE = isInteractive(analysis);
    const allowTimeExtn = allowAnalysisTimeExtn(analysis, username);
    const [relaunchHref, relaunchAs] = useRelaunchLink(analysis);
    const [outputFolderHref, outputFolderAs] = useGotoOutputFolderLink(
        analysis?.resultfolderid
    );
    return (
        <>
            <Link href={outputFolderHref} as={outputFolderAs} passHref>
                <GotoOutputFolderButton baseId={baseId} />
            </Link>
            {allowBatchDrillDown && isBatch && (
                <IconButton
                    size="small"
                    onClick={(event) => {
                        event.stopPropagation();
                        handleBatchIconClick(analysis);
                    }}
                    id={build(baseId, ids.ICONS.BATCH, ids.BUTTON)}
                    color="primary"
                    title={t("htDetails")}
                >
                    <UnfoldMoreIcon fontSize="small" />
                </IconButton>
            )}
            {!isDisabled && !isVICE && (
                <Link href={relaunchHref} as={relaunchAs} passHref>
                    <RelaunchButton baseId={baseId} />
                </Link>
            )}
            {isVICE && (
                <IconButton
                    onClick={() =>
                        handleInteractiveUrlClick(interactiveUrls[0])
                    }
                    size="small"
                    id={build(baseId, ids.ICONS.INTERACTIVE, ids.BUTTON)}
                    color="primary"
                    title={t("goToVice")}
                >
                    <LaunchIcon fontSize="small" />
                </IconButton>
            )}
            {allowTimeExtn && (
                <IconButton
                    id={build(baseId, ids.ICONS.TIME_LIMIT)}
                    size="small"
                    color="primary"
                    title={t("extendTime")}
                >
                    <HourGlass fontSize="small" />
                </IconButton>
            )}
            <IconButton
                onClick={() => handleDetailsClick(analysis)}
                size="small"
                color="primary"
                title={t("details")}
            >
                <Info fontSize="small" />
            </IconButton>
        </>
    );
}
