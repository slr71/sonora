/**
 * Form field for editing App validator rule IntBelow params.
 *
 * @author psarando
 */
import React from "react";

import { FastField } from "formik";

import ids from "../../ids";

import { build as buildID, FormIntegerField } from "@cyverse-de/ui-lib";

export default function IntBelowField(props) {
    const { baseId, fieldName } = props;

    return (
        <FastField
            id={buildID(baseId, ids.PARAM_FIELDS.ARGUMENT_OPTION)}
            name={`${fieldName}.params.0`}
            component={FormIntegerField}
        />
    );
}