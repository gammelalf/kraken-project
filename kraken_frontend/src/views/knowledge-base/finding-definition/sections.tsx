import { editor } from "monaco-editor";
import React from "react";
import { EditorTarget, FindingSection } from "../../../api/generated";
import BandageIcon from "../../../svg/bandage";
import BookIcon from "../../../svg/book";
import FlameIcon from "../../../svg/flame";
import InformationIcon from "../../../svg/information";
import LibraryIcon from "../../../svg/library";
import PersonCircleIcon from "../../../svg/person-circle";
import { useModel } from "../../../utils/model-controller";
import ITextModel = editor.ITextModel;

/** State object provided by {@link useSectionsState `useSectionsState`} */
export type Sections = Record<
    FindingSection,
    {
        /** This section's content */
        value: string;
        /** Setter for this section's content */
        set: (newValue: string, target?: EditorTarget) => void;
        /** Model storing this section's content */
        model: ITextModel | null;

        /** Selects this section */
        select(): void;
        /** Is this section selected? */
        selected: boolean;
    }
> & {
    /** The currently selected section */
    selected: FindingSection;
};

/**
 * {@link useModel `useModel`} specialized for storing a finding definition's sections
 *
 * Besides just storing the sections' models, it also stores a `selected` state.
 *
 * @returns monaco models and selection state for the different sections of a finding definition
 */
export function useSectionsState(): Sections {
    const [summary, setSummary, summaryModel] = useModel({});
    const [description, setDescription, descriptionModel] = useModel({ language: "markdown" });
    const [impact, setImpact, impactModel] = useModel({ language: "markdown" });
    const [remediation, setRemediation, remediationModel] = useModel({ language: "markdown" });
    const [references, setReferences, referencesModel] = useModel({ language: "markdown" });

    const [selectedSection, setSelectedSection] = React.useState<FindingSection>(FindingSection.Summary);

    return {
        Summary: {
            value: summary,
            set: setSummary,
            model: summaryModel,
            // eslint-disable-next-line jsdoc/require-jsdoc
            select: () => setSelectedSection(FindingSection.Summary),
            selected: selectedSection === FindingSection.Summary,
        },
        Description: {
            value: description,
            set: setDescription,
            model: descriptionModel,
            // eslint-disable-next-line jsdoc/require-jsdoc
            select: () => setSelectedSection(FindingSection.Description),
            selected: selectedSection === FindingSection.Description,
        },
        Impact: {
            value: impact,
            set: setImpact,
            model: impactModel,
            // eslint-disable-next-line jsdoc/require-jsdoc
            select: () => setSelectedSection(FindingSection.Impact),
            selected: selectedSection === FindingSection.Impact,
        },
        Remediation: {
            value: remediation,
            set: setRemediation,
            model: remediationModel,
            // eslint-disable-next-line jsdoc/require-jsdoc
            select: () => setSelectedSection(FindingSection.Remediation),
            selected: selectedSection === FindingSection.Remediation,
        },
        References: {
            value: references,
            set: setReferences,
            model: referencesModel,
            // eslint-disable-next-line jsdoc/require-jsdoc
            select: () => setSelectedSection(FindingSection.References),
            selected: selectedSection === FindingSection.References,
        },
        selected: selectedSection,
    };
}

/** Properties for {@link SectionSelectionTabs `<SectionSelectionTabs />`} */
export type SectionSelectionTabsProps = {
    /** The sections' selection state and their setters */
    sections: Record<
        FindingSection,
        {
            /** Selects this section */
            select(): void;
            /** Is this section selected? */
            selected: boolean;
        }
    >;

    /** Optional booleans indicating whether another user is currently in a section */
    others?: Record<FindingSection, boolean>;
};

/** Little tab bar next to an `<Editor />` to switch between sections */
export function SectionSelectionTabs(props: SectionSelectionTabsProps) {
    const { sections, others } = props;
    return (
        <div className={"knowledge-base-editor-tabs"}>
            <button
                title={"Summary"}
                className={`knowledge-base-editor-tab ${sections.Summary.selected ? "selected" : ""}`}
                onClick={sections.Summary.select}
            >
                <InformationIcon />
                {others && others.Summary ? <PersonCircleIcon /> : null}
            </button>
            <button
                title={"Description"}
                className={`knowledge-base-editor-tab ${sections.Description.selected ? "selected" : ""}`}
                onClick={sections.Description.select}
            >
                <BookIcon />
                {others && others.Description ? <PersonCircleIcon /> : null}
            </button>
            <button
                title={"Impact"}
                className={`knowledge-base-editor-tab ${sections.Impact.selected ? "selected" : ""}`}
                onClick={sections.Impact.select}
            >
                <FlameIcon />
                {others && others.Impact ? <PersonCircleIcon /> : null}
            </button>
            <button
                title={"Remediation"}
                className={`knowledge-base-editor-tab ${sections.Remediation.selected ? "selected" : ""}`}
                onClick={sections.Remediation.select}
            >
                <BandageIcon />
                {others && others.Remediation ? <PersonCircleIcon /> : null}
            </button>
            <button
                title={"References"}
                className={`knowledge-base-editor-tab ${sections.References.selected ? "selected" : ""}`}
                onClick={sections.References.select}
            >
                <LibraryIcon />
                {others && others.References ? <PersonCircleIcon /> : null}
            </button>
        </div>
    );
}
