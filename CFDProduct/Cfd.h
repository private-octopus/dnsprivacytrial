#pragma once
class Cfd
{
public:
    Cfd();
    ~Cfd();

    bool Load(char * fname);
    bool AddPoint(double v, double p);
    double GetProba(double v);
    double GetValue(double p);

private:
    unsigned int nb_points;
    unsigned int nb_points_alloc;
    double * value;
    double * proba;

    bool Resize();

};

