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
 * The certainty of a manually added host
 * @export
 */
export const ManualHostCertainty = {
    Historical: 'Historical',
    SupposedTo: 'SupposedTo'
} as const;
export type ManualHostCertainty = typeof ManualHostCertainty[keyof typeof ManualHostCertainty];


export function ManualHostCertaintyFromJSON(json: any): ManualHostCertainty {
    return ManualHostCertaintyFromJSONTyped(json, false);
}

export function ManualHostCertaintyFromJSONTyped(json: any, ignoreDiscriminator: boolean): ManualHostCertainty {
    return json as ManualHostCertainty;
}

export function ManualHostCertaintyToJSON(value?: ManualHostCertainty | null): any {
    return value as any;
}

