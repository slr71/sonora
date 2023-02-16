import React from "react";

import { useTranslation } from "i18n";
import { Table, TableBody, TableCell, Typography } from "@material-ui/core";
import SimpleExpansionPanel from "components/tools/SimpleExpansionPanel";
import { DERow } from "components/table/DERow";
import DETableHead from "components/table/DETableHead";

import ids from "../ids";

import EmptyTable from "components/table/EmptyTable";
import { formatFileSize } from "components/data/utils";

const TABLE_COLUMNS = [
    { name: "Usage", numeric: false, enableSorting: false },
    { name: "Name", numeric: false, enableSorting: false },
];

function Usages(props) {
    const { parentId, usages } = props;
    const { t } = useTranslation("subscriptions");

    return (
        <SimpleExpansionPanel
            parentId={parentId}
            header={t("usages")}
            defaultExpanded={false}
        >
            <Table>
                <TableBody>
                    {(!usages || usages.length === 0) && (
                        <EmptyTable
                            message={t("noUsages")}
                            numColumns={TABLE_COLUMNS.length}
                        />
                    )}
                    {usages &&
                        usages.length > 0 &&
                        usages.map((resource, index) => (
                            <UsageAmounts index={index} resource={resource} />
                        ))}
                </TableBody>
                <DETableHead
                    selectable={false}
                    rowCount={usages ? usages.length : 0}
                    baseId={parentId}
                    ids={ids.USAGES_TABLE}
                    columnData={TABLE_COLUMNS}
                />
            </Table>
        </SimpleExpansionPanel>
    );
}

function UsageAmounts(props) {
    const { index, resource } = props;
    let usageInBytes = resource.resource_type.unit.toLowerCase() === "bytes";
    if (usageInBytes) {
        return (
            <DERow tabIndex={-1} key={index}>
                <TableCell>
                    <Typography>
                        {formatFileSize(resource.usage).split(" ")[0]}
                    </Typography>
                </TableCell>
                <TableCell>
                    <Typography>
                        {formatFileSize(resource.usage).split(" ")[1]}
                    </Typography>
                </TableCell>
            </DERow>
        );
    } else {
        return (
            <DERow tabIndex={-1} key={index}>
                <TableCell>
                    <Typography>{resource.usage}</Typography>
                </TableCell>
                <TableCell>
                    <Typography>{resource.resource_type.unit}</Typography>
                </TableCell>
            </DERow>
        );
    }
}

export default Usages;
