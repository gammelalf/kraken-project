/* tslint:disable */
/* eslint-disable */
/**
 * kraken
 * The core component of kraken-project
 *
 * The version of the OpenAPI document: 0.4.2
 * Contact: git@omikron.dev
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */

import { exists, mapValues } from '../runtime';
import type { FindingSeverity } from './FindingSeverity';
import {
    FindingSeverityFromJSON,
    FindingSeverityFromJSONTyped,
    FindingSeverityToJSON,
} from './FindingSeverity';

/**
 * The request to update a new finding definition
 * @export
 * @interface UpdateFindingDefinitionRequest
 */
export interface UpdateFindingDefinitionRequest {
    /**
     * Name of the new finding definition
     * 
     * This must be unique
     * @type {string}
     * @memberof UpdateFindingDefinitionRequest
     */
    name?: string | null;
    /**
     * 
     * @type {FindingSeverity}
     * @memberof UpdateFindingDefinitionRequest
     */
    severity?: FindingSeverity | null;
    /**
     * Optional linked CVE
     * @type {string}
     * @memberof UpdateFindingDefinitionRequest
     */
    cve?: string | null;
    /**
     * Expected time duration required for the remediation
     * @type {string}
     * @memberof UpdateFindingDefinitionRequest
     */
    remediationDuration?: string | null;
    /**
     * List of categories
     * @type {Array<string>}
     * @memberof UpdateFindingDefinitionRequest
     */
    categories?: Array<string> | null;
}

/**
 * Check if a given object implements the UpdateFindingDefinitionRequest interface.
 */
export function instanceOfUpdateFindingDefinitionRequest(value: object): boolean {
    let isInstance = true;

    return isInstance;
}

export function UpdateFindingDefinitionRequestFromJSON(json: any): UpdateFindingDefinitionRequest {
    return UpdateFindingDefinitionRequestFromJSONTyped(json, false);
}

export function UpdateFindingDefinitionRequestFromJSONTyped(json: any, ignoreDiscriminator: boolean): UpdateFindingDefinitionRequest {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'name': !exists(json, 'name') ? undefined : json['name'],
        'severity': !exists(json, 'severity') ? undefined : FindingSeverityFromJSON(json['severity']),
        'cve': !exists(json, 'cve') ? undefined : json['cve'],
        'remediationDuration': !exists(json, 'remediation_duration') ? undefined : json['remediation_duration'],
        'categories': !exists(json, 'categories') ? undefined : json['categories'],
    };
}

export function UpdateFindingDefinitionRequestToJSON(value?: UpdateFindingDefinitionRequest | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'name': value.name,
        'severity': FindingSeverityToJSON(value.severity),
        'cve': value.cve,
        'remediation_duration': value.remediationDuration,
        'categories': value.categories,
    };
}

