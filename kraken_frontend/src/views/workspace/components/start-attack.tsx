import React from "react";

export type StartAttackProps = {
    active: boolean;
};

export default function StartAttack(props: StartAttackProps) {
    const { active } = props;
    return (
        <div className={"start-attack-container"}>
            <button type={"submit"} className={"start-attack-button"} disabled={!active}>
                <svg
                    width={285}
                    height={285}
                    viewBox="0 0 75.841 75.296"
                    className={active ? "start-attack" : "start-attack-disabled"}
                >
                    <g>
                        <path
                            d="m73.618 107.264-31.586 18.279-31.623-18.215-.037-36.493 31.586-18.279L73.58 70.771Z"
                            transform="translate(-9.372 -51.401)"
                            className={"kraken-attacks-hex"}
                        />
                        <path
                            d="M71.181 52.365c-6.495-3.893-14.916-1.783-18.808 4.712-3.893 6.495-1.783 14.916 4.712 18.808C63.58 79.778 72 77.668 75.893 71.173c3.893-6.495 1.783-14.916-4.712-18.808zM59.638 71.518a1.548 1.548 0 1 1 1.591-2.656 1.548 1.548 0 0 1-1.591 2.656zm.892 4.478c.114-.396.04-.944.04-.944.91-.335.723-1.242.723-1.242.879-.14.853-.993.853-.993 1.805.931 5.02 1.59 6.056 1.76 1.037.17 1.593-.291 1.593-.291.48-.335.745-1.315.268-1.343-3.596-.213-6.657-1.476-7.318-3.097-.419-1.027-.336-2.952-.336-2.952s-1.658.98-2.762 1.095c-1.741.181-4.298-1.923-6.18-4.993-.25-.408-.99.288-1.06.87 0 0-.144.707.495 1.541.638.834 2.735 3.358 4.407 4.511 0 0-.764.38-.473 1.22 0 0-.888.263-.755 1.224 0 0-.525.195-.82.487-3.936-3.946-4.853-10.2-1.858-15.198 3.025-5.047 9.06-7.179 14.436-5.477-.835 1.724-4.509 7.858-5.022 8.649-.562.866-2.201 3.106-3.067 4.048-.866.943-2.34 1.82-2.34 1.82 1.98 2.003 5.074-.46 5.074-.46L70.27 53.24c.096.056.117.067.175.102l.157.097-7.786 12.99s-.644 3.933 2.056 4.735c0 0 .13-1.684.553-2.891.423-1.208 1.632-3.706 2.13-4.61.456-.826 4.121-6.96 5.246-8.513 4.03 3.939 4.995 10.263 1.971 15.308-2.989 4.988-8.916 7.13-14.242 5.538z"
                            transform="matrix(1.65365 0 0 1.65365 -73.43 -68.392)"
                        />
                    </g>
                </svg>
            </button>
            <span className={"neon"}>Start Attack</span>
        </div>
    );
}
