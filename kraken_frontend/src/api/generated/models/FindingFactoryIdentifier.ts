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


/**
 * Enum identifying specific kinds of issues the finding factory might detect and create findings for.
 * @export
 */
export const FindingFactoryIdentifier = {
    ServiceDetectionPostgres: 'ServiceDetectionPostgres',
    ServiceDetectionMariaDb: 'ServiceDetectionMariaDb',
    ServiceDetectionSsh: 'ServiceDetectionSsh',
    ServiceDetectionSnmp: 'ServiceDetectionSnmp'
} as const;
export type FindingFactoryIdentifier = typeof FindingFactoryIdentifier[keyof typeof FindingFactoryIdentifier];


export function FindingFactoryIdentifierFromJSON(json: any): FindingFactoryIdentifier {
    return FindingFactoryIdentifierFromJSONTyped(json, false);
}

export function FindingFactoryIdentifierFromJSONTyped(json: any, ignoreDiscriminator: boolean): FindingFactoryIdentifier {
    return json as FindingFactoryIdentifier;
}

export function FindingFactoryIdentifierToJSON(value?: FindingFactoryIdentifier | null): any {
    return value as any;
}

