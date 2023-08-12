const { readBinFile } = require("@iden3/binfileutils");
const { BigBuffer } = require("ffjavascript");
const { Keccak256Transcript } = require("./Keccak256Transcript");
const { Polynomial } = require("./polynomial/polynomial");
const readPTauHeader = require("./ptau_utils");

module.exports = async function kzg_basic_prover(evalsBufferArray, pTauFilename, options) {
    const logger = options.logger;

    if (logger) logger.info("> KZG BASIC PROVER STARTED");

    const { fd: fdPTau, sections: pTauSections } = await readBinFile(pTauFilename, "ptau", 1, 1 << 22, 1 << 24);
    const { curve, power: nBitsPTau } = await readPTauHeader(fdPTau, pTauSections);

    // STEP 0. Get the settings and prepare the setup    

    // Ensure all polynomials have the same length
    let polLen = 0;
    for (let i = 0; i < evalsBufferArray.length; i++) {
        polLen = Math.max(polLen, evalsBufferArray[i].byteLength);
    }
    polLen /= curve.Fr.n8;
    
    const nBits = Math.ceil(Math.log2(polLen));
    const domainSize = 2 ** nBits;

    // Ensure the polynomial has a length that is a power of two.
    if (polLen !== domainSize) {
        throw new Error("Polynomial length must be power of two.");
    }

    // Ensure the powers of Tau file is sufficiently large
    if (nBitsPTau < nBits) {
        throw new Error("Powers of Tau has not enough values for this polynomial");
    }

    const sG1 = curve.G1.F.n8 * 2;

    const PTau = new BigBuffer(domainSize * sG1);
    await fdPTau.readToBuffer(PTau, 0, domainSize * sG1, pTauSections[2][0].p);

    if (logger) {
        logger.info("-------------------------------");
        logger.info("  KZG BASIC PROVER SETTINGS");
        logger.info(`  Curve:        ${curve.name}`);
        logger.info(`  #polynomials: ${evalsBufferArray.length}`);
        logger.info("-------------------------------");
    }

    let proof = {};
    let challenges = {};

    const pols = [];
    for (let i = 0; i < evalsBufferArray.length; i++) {
        // Convert the evaluations to Montgomery form
        const evals = await curve.Fr.batchToMontgomery(evalsBufferArray[i]);
    
        // Get the polynomials from the evaluations
        pols[i] = await Polynomial.fromEvaluations(evals, curve, logger);
    }

    // STEP 1. Generate the polynomial commitments for all polynomials
    logger.info("> STEP 1. Compute polynomial commitments");
    proof.commitments = [];
    for(let i=0; i<pols.length; i++) {
        pols[i].coef = await curve.Fr.batchToMontgomery(pols[i].coef.slice(0, pols[i].coef.byteLength));
        proof.commitments[i] = await pols[i].multiExponentiation(PTau, `pol${i}`);
        logger.info(`··· [p${i}(X)]_1 =`, curve.G1.toString(proof.commitments[i]));
    }

    // STEP 2. Compute opening evaluations
    logger.info("> STEP 2. Compute opening evaluations");
    // STEP 2.1 Compute challenge xi
    const transcript = new Keccak256Transcript(curve);
    for(commitment of proof.commitments) transcript.addPolCommitment(commitment);
    challenges.xi = transcript.getChallenge();
    logger.info("··· xi =", curve.Fr.toString(challenges.xi));

    // STEP 2.2 Compute evaluations
    proof.evaluations = [];
    for(let i=0; i<pols.length; i++) {
        proof.evaluations[i] = pols[i].evaluate(challenges.xi);
        logger.info(`··· y${i} =`, curve.Fr.toString(proof.evaluations[i]));
    }

    // STEP 3. Calculate the polynomial q(X)
    logger.info("> STEP 3. Calculate the polynomial q(X)");
    // STEP 3.1 Compute challenge alpha
    transcript.reset();
    for(evaluation of proof.evaluations) transcript.addEvaluation(evaluation);
    challenges.alpha = transcript.getChallenge();
    logger.info("··· alpha =", curve.Fr.toString(challenges.alpha));

    // STEP 3.1 Calculate the polynomial q(X)
    let polQ = new Polynomial(new Uint8Array(curve.Fr.n8 * polLen), curve, logger);

    let currentAlpha = curve.Fr.one;
    for(let i=0; i<pols.length; i++) {
        pols[i].subScalar(proof.evaluations[i]);
        pols[i].divByXSubValue(challenges.xi);
        pols[i].mulScalar(currentAlpha);

        polQ.add(pols[i]);
        currentAlpha = curve.Fr.mul(currentAlpha, challenges.alpha);
    }

    proof.commitQ = await polQ.multiExponentiation(PTau, "Q");
    logger.info("··· [q(X)]_1 =", curve.G1.toString(proof.commitQ));

    if (logger) logger.info("> KZG BASIC PROVER FINISHED");

    await fdPTau.close();

    return proof;
};
