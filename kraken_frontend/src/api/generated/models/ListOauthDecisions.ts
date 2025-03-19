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

import { exists, mapValues } from '../runtime';
import type { FullOauthDecision } from './FullOauthDecision';
import {
    FullOauthDecisionFromJSON,
    FullOauthDecisionFromJSONTyped,
    FullOauthDecisionToJSON,
} from './FullOauthDecision';

/**
 * Response holding a user's oauth decisions
 * @export
 * @interface ListOauthDecisions
 */
export interface ListOauthDecisions {
    /**
     * A user's oauth decisions
     * @type {Array<FullOauthDecision>}
     * @memberof ListOauthDecisions
     */
    decisions: Array<FullOauthDecision>;
}

/**
 * Check if a given object implements the ListOauthDecisions interface.
 */
export function instanceOfListOauthDecisions(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "decisions" in value;

    return isInstance;
}

export function ListOauthDecisionsFromJSON(json: any): ListOauthDecisions {
    return ListOauthDecisionsFromJSONTyped(json, false);
}

export function ListOauthDecisionsFromJSONTyped(json: any, ignoreDiscriminator: boolean): ListOauthDecisions {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'decisions': ((json['decisions'] as Array<any>).map(FullOauthDecisionFromJSON)),
    };
}

export function ListOauthDecisionsToJSON(value?: ListOauthDecisions | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'decisions': ((value.decisions as Array<any>).map(FullOauthDecisionToJSON)),
    };
}

