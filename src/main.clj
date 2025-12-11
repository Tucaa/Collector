(ns main
  (:gen-class)) ;Za runovanje paketa


;Ovde ce da baci sintaksnu gresku ovo ti je samo da bi naucio da radis
;(map fn (+ % 50)
;     map
;     (fn [line]
;       (Integer/parseInt
;         (str (if (= \R (first line)) "+" "-")
;              (subs line 1))))
;     (clojure.string/split-lines (slurp "src/testnew.txt")))

(defn read-lines [loaded]
  (try
    (when loaded ;
      (clojure.string/split-lines loaded))
    (catch Exception e
      (println (str "Unexpected error occurred: " (.getMessage e)))
      nil)))


(defn safe-slurp [file-path]
    (slurp file-path))


(defn plusminus [s]
  ;
  (let [f_string (if (.startsWith s "L")
                          (str "-" (subs s 1))
                          ;Stavlja se empty stirng posto ne mora + posto je svakako pozitivan broj
                          (str "" (subs s 1)))]

    (Integer/parseInt f_string)))

;Ova funkcija je dodata zato sto clojure -10/100 racuna kao nulu
;Ova funkcija vraca -1
;Long trimuje decimalni deo
(defn floor_f [num1, num2]
  (long (Math/floor (/ num1 num2)))
  )

(defn pwd_f [numbers]
  ;; Definiše se hash mapa sa početnom pozicijom i brojačem
  (let [initial {:start 50 :count 0 :count2 0}]
    (reduce (fn [acc num]
              ;; Stavlja se trenutna pozicija na akumulator
              (let [cur_pos (:start acc)
                    ;Racunanje nove pozicije
                    ;Ukupno sabiranje sabira se ukupan broj
                    total (+ cur_pos num)
                    new_pos (mod (+ cur_pos num) 100)
                    ;Ako je nova pozicija 0 dodaje se u count
                    new-count (if (= new_pos 0) ;(zero? new_pos) Moze i ovako
                                (inc (:count acc))
                                (:count acc))

                    clicks (if (> num 0)
                                  ;Ako je pozitivan borj ona se racuna razlika celobrojnog deljenja (50 i 1000) > 1050 / 100 == 10 - 50/100 == 0 ukupno 10
                                  (- (quot total 100) (quot cur_pos 100))
                                  ;U suprotnom se
                                  (- (floor_f (dec cur_pos) 100) (floor_f (dec total) 100)))
                    new-count2 (+ (:count2 acc) clicks)]
                    ;Stari pristup nije davao dobar rezultat davao je 5805 umesto 5820 Nije uzimao u obir na primer kada se pocne na 99 pa doda 100 prodje se 0 2 puta
                    ;Drugi count kada predje preko nule racuna se ako je broj i trenutni veci od 100 ili je razlika brojeva manja od nule
                    ;new-count2 (cond
                                 ;
                                 ;;Negativan broj proverava se da li je broj koji treba da se odume veci od broja od kojeg se oduzima
                                 ;(< num 0)
                                 ;(if (> (Math/abs num) 100)
                                 ;  (inc (:count2 (update acc :count2 + (quot (Math/abs num) 100)))) ;Mora apsolutna zato sto je ovde negativan broj
                                 ;  (if (> (Math/abs num) cur_pos)
                                 ;    (inc (:count2 acc))
                                 ;    (:count2 acc)))
                                 ;
                                 ;
                                 ;;Pozitivan proverava se da li je zbir 2 broja veci od 100 (znaci presao je 1000)
                                 ;(> num 0)
                                 ;(if (> (Math/abs num) 100)
                                 ;  (inc (:count2 (update acc :count2 + (quot num 100))))
                                 ;  (if (> (+ cur_pos num) 100)
                                 ;    (inc (:count2 acc))
                                 ;    (:count2 acc)))
                                 ;
                                 ;; Prebaceno u uslove gore (uslov if (> (Math/abs num) 100))
                                 ;;Kod ovog uslova treba da se uradi celobrojno sa 100 taj broj se dodaje u drugi brojac
                                 ;; Treba mi ostatak
                                 ;; Ostatak bi trebalo da se provuce kroz gornja 2 uslova
                                 ;
                                 ;:else
                                 ;(:count2 acc))]

                (println "Trenutna:" cur_pos " num:" num " -> Sledeca:" new_pos "Acc:" acc)

                {:start new_pos :count new-count :count2 new-count2 }))

            ;Ovde je inicijalna vrednost brojaca
            initial
            ;Ovde je sequenca brojeva nad kojom se vrsi reduce
            numbers)))


;Obicna rekurzija backa stack overflow kada se pozove sa velikim brojem
(defn sum [n]
  (if (zero? n)
    0
    (+ n (sum (dec n)))))



;Testiranje loop /recur
(defn sum_recur [n]
  (loop [i n
         acc 0]
    (if (zero? i)
      acc
      (recur (dec i) (+ acc i)))))

(defn fib [n]
  ;Uslov ako se stavi 1 ili 0
  (cond
    (= n 0) '[0]
    (= n 1) '[0 1]
    :else
    (loop [acc 2 ; Brojac stavljen na 2 posto se krece od 2 ako je usa u ovaj uslov
            x-1 0 ; Prethodni broj
            x 1 ; Trenutni broj
            vec [0 1]]
      (if (> acc n)
        ;Konvertovanje vektora u listu
        (seq vec)
        (recur (inc acc) x (+ x-1 x)(conj vec (+ x-1 x)))))))

(defn pos_test
  ([] (pos_test 1))
  ([n] (lazy-seq (cons n (pos_test (inc n))))))


(defn fib_lazy
  ;Iniciijalizuje se prazna sekvenca
  ([] (fib_lazy 0 1))
  ([x, y] (lazy-seq (cons x (fib_lazy y (+ x y))))))



(defn -main
  [& args]

  (let [test (pwd_f (map plusminus (read-lines (safe-slurp "src/test.txt"))))]
    (if test
      (println "Uspesno provaljena sifra:\n" test)
      (println "Niije ucitao fajl")))

  (println "Testiranje sumiranja"(sum_recur 5))
  (println "Fibonaci recur" (fib 5))
  (println "Testiranje lazy seq"(take 5 (pos_test)))
  (println "Fibonaci lazy"(take 5 (fib_lazy)))
  )




