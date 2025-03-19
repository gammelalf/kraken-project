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

import {
    SearchResultEntryOneOf,
    instanceOfSearchResultEntryOneOf,
    SearchResultEntryOneOfFromJSON,
    SearchResultEntryOneOfFromJSONTyped,
    SearchResultEntryOneOfToJSON,
} from './SearchResultEntryOneOf';
import {
    SearchResultEntryOneOf1,
    instanceOfSearchResultEntryOneOf1,
    SearchResultEntryOneOf1FromJSON,
    SearchResultEntryOneOf1FromJSONTyped,
    SearchResultEntryOneOf1ToJSON,
} from './SearchResultEntryOneOf1';
import {
    SearchResultEntryOneOf10,
    instanceOfSearchResultEntryOneOf10,
    SearchResultEntryOneOf10FromJSON,
    SearchResultEntryOneOf10FromJSONTyped,
    SearchResultEntryOneOf10ToJSON,
} from './SearchResultEntryOneOf10';
import {
    SearchResultEntryOneOf2,
    instanceOfSearchResultEntryOneOf2,
    SearchResultEntryOneOf2FromJSON,
    SearchResultEntryOneOf2FromJSONTyped,
    SearchResultEntryOneOf2ToJSON,
} from './SearchResultEntryOneOf2';
import {
    SearchResultEntryOneOf3,
    instanceOfSearchResultEntryOneOf3,
    SearchResultEntryOneOf3FromJSON,
    SearchResultEntryOneOf3FromJSONTyped,
    SearchResultEntryOneOf3ToJSON,
} from './SearchResultEntryOneOf3';
import {
    SearchResultEntryOneOf4,
    instanceOfSearchResultEntryOneOf4,
    SearchResultEntryOneOf4FromJSON,
    SearchResultEntryOneOf4FromJSONTyped,
    SearchResultEntryOneOf4ToJSON,
} from './SearchResultEntryOneOf4';
import {
    SearchResultEntryOneOf5,
    instanceOfSearchResultEntryOneOf5,
    SearchResultEntryOneOf5FromJSON,
    SearchResultEntryOneOf5FromJSONTyped,
    SearchResultEntryOneOf5ToJSON,
} from './SearchResultEntryOneOf5';
import {
    SearchResultEntryOneOf6,
    instanceOfSearchResultEntryOneOf6,
    SearchResultEntryOneOf6FromJSON,
    SearchResultEntryOneOf6FromJSONTyped,
    SearchResultEntryOneOf6ToJSON,
} from './SearchResultEntryOneOf6';
import {
    SearchResultEntryOneOf7,
    instanceOfSearchResultEntryOneOf7,
    SearchResultEntryOneOf7FromJSON,
    SearchResultEntryOneOf7FromJSONTyped,
    SearchResultEntryOneOf7ToJSON,
} from './SearchResultEntryOneOf7';
import {
    SearchResultEntryOneOf8,
    instanceOfSearchResultEntryOneOf8,
    SearchResultEntryOneOf8FromJSON,
    SearchResultEntryOneOf8FromJSONTyped,
    SearchResultEntryOneOf8ToJSON,
} from './SearchResultEntryOneOf8';
import {
    SearchResultEntryOneOf9,
    instanceOfSearchResultEntryOneOf9,
    SearchResultEntryOneOf9FromJSON,
    SearchResultEntryOneOf9FromJSONTyped,
    SearchResultEntryOneOf9ToJSON,
} from './SearchResultEntryOneOf9';

/**
 * @type SearchResultEntry
 * Dynamic result of a search
 * @export
 */
export type SearchResultEntry = SearchResultEntryOneOf | SearchResultEntryOneOf1 | SearchResultEntryOneOf10 | SearchResultEntryOneOf2 | SearchResultEntryOneOf3 | SearchResultEntryOneOf4 | SearchResultEntryOneOf5 | SearchResultEntryOneOf6 | SearchResultEntryOneOf7 | SearchResultEntryOneOf8 | SearchResultEntryOneOf9;

export function SearchResultEntryFromJSON(json: any): SearchResultEntry {
    return SearchResultEntryFromJSONTyped(json, false);
}

export function SearchResultEntryFromJSONTyped(json: any, ignoreDiscriminator: boolean): SearchResultEntry {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return { ...SearchResultEntryOneOfFromJSONTyped(json, true), ...SearchResultEntryOneOf1FromJSONTyped(json, true), ...SearchResultEntryOneOf10FromJSONTyped(json, true), ...SearchResultEntryOneOf2FromJSONTyped(json, true), ...SearchResultEntryOneOf3FromJSONTyped(json, true), ...SearchResultEntryOneOf4FromJSONTyped(json, true), ...SearchResultEntryOneOf5FromJSONTyped(json, true), ...SearchResultEntryOneOf6FromJSONTyped(json, true), ...SearchResultEntryOneOf7FromJSONTyped(json, true), ...SearchResultEntryOneOf8FromJSONTyped(json, true), ...SearchResultEntryOneOf9FromJSONTyped(json, true) };
}

export function SearchResultEntryToJSON(value?: SearchResultEntry | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }

    if (instanceOfSearchResultEntryOneOf(value)) {
        return SearchResultEntryOneOfToJSON(value as SearchResultEntryOneOf);
    }
    if (instanceOfSearchResultEntryOneOf1(value)) {
        return SearchResultEntryOneOf1ToJSON(value as SearchResultEntryOneOf1);
    }
    if (instanceOfSearchResultEntryOneOf10(value)) {
        return SearchResultEntryOneOf10ToJSON(value as SearchResultEntryOneOf10);
    }
    if (instanceOfSearchResultEntryOneOf2(value)) {
        return SearchResultEntryOneOf2ToJSON(value as SearchResultEntryOneOf2);
    }
    if (instanceOfSearchResultEntryOneOf3(value)) {
        return SearchResultEntryOneOf3ToJSON(value as SearchResultEntryOneOf3);
    }
    if (instanceOfSearchResultEntryOneOf4(value)) {
        return SearchResultEntryOneOf4ToJSON(value as SearchResultEntryOneOf4);
    }
    if (instanceOfSearchResultEntryOneOf5(value)) {
        return SearchResultEntryOneOf5ToJSON(value as SearchResultEntryOneOf5);
    }
    if (instanceOfSearchResultEntryOneOf6(value)) {
        return SearchResultEntryOneOf6ToJSON(value as SearchResultEntryOneOf6);
    }
    if (instanceOfSearchResultEntryOneOf7(value)) {
        return SearchResultEntryOneOf7ToJSON(value as SearchResultEntryOneOf7);
    }
    if (instanceOfSearchResultEntryOneOf8(value)) {
        return SearchResultEntryOneOf8ToJSON(value as SearchResultEntryOneOf8);
    }
    if (instanceOfSearchResultEntryOneOf9(value)) {
        return SearchResultEntryOneOf9ToJSON(value as SearchResultEntryOneOf9);
    }

    return {};
}

