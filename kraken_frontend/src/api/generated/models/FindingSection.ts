/* tslint:disable */
/* eslint-disable */
/**
 * kraken
 * The core component of kraken-project
 *
 * The version of the OpenAPI document: 0.5.0
 * Contact: git@omikron.dev
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


/**
 * The definition section that was edited
 * @export
 */
export const FindingSection = {
    Summary: 'Summary',
    Description: 'Description',
    Impact: 'Impact',
    Remediation: 'Remediation',
    References: 'References'
} as const;
export type FindingSection = typeof FindingSection[keyof typeof FindingSection];


export function FindingSectionFromJSON(json: any): FindingSection {
    return FindingSectionFromJSONTyped(json, false);
}

export function FindingSectionFromJSONTyped(json: any, ignoreDiscriminator: boolean): FindingSection {
    return json as FindingSection;
}

export function FindingSectionToJSON(value?: FindingSection | null): any {
    return value as any;
}

